/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved. */

#define __user         __attribute__((noderef, address_space(1)))
#define static_assert(a, b)
#define __counted_by(a)

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <xf86drm.h>
#include <xf86drmMode.h>
#include <time.h>
#include <poll.h>
#include <dirent.h>
#include <amdxdna_accel.h>

#include <sys/mman.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#include "virtgpu_drm.h"
#include "amdxdna_proto.h"

static uint64_t *resp_buf;
static uint64_t heap_addr;
static uint64_t heap_xdna_addr;

static inline int sync_wait(int fd, int timeout)
{
	struct pollfd fds = {0};
	int ret;
	struct timespec poll_start, poll_end;

	fds.fd = fd;
	fds.events = POLLIN;

	do {
		clock_gettime(CLOCK_MONOTONIC, &poll_start);
		ret = poll(&fds, 1, timeout);
		clock_gettime(CLOCK_MONOTONIC, &poll_end);
		if (ret > 0) {
			if (fds.revents & (POLLERR | POLLNVAL)) {
				errno = EINVAL;
				return -1;
			}
			return 0;
		} else if (ret == 0) {
			errno = ETIME;
			return -1;
		}
		timeout -= (poll_end.tv_sec - poll_start.tv_sec) * 1000 +
			(poll_end.tv_nsec - poll_end.tv_nsec) / 1000000;
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN));

	return ret;
}

/* virglrenderer_hw.h */
#define VIRGL_RENDERER_CAPSET_DRM 6

static int
set_context(int fd)
{
   struct drm_virtgpu_context_set_param params[] = {
         { VIRTGPU_CONTEXT_PARAM_CAPSET_ID, VIRGL_RENDERER_CAPSET_DRM },
         { VIRTGPU_CONTEXT_PARAM_NUM_RINGS, 64 },
   };
   struct drm_virtgpu_context_init args = {
      .num_params = ARRAY_SIZE(params),
      .ctx_set_params = (uintptr_t)params,
   };

   return drmIoctl(fd, DRM_IOCTL_VIRTGPU_CONTEXT_INIT, &args);
}

void *map_handle(int fd, uint32_t handle, size_t size)
{
	struct drm_virtgpu_map req = {
		.handle = handle,
	};
	void *addr;
	int ret;

	ret = drmIoctl(fd, DRM_IOCTL_VIRTGPU_MAP, &req);
	if (ret < 0) {
		printf("Map BO failed with %s\n", strerror(errno));
		return NULL;
	}
	if (!size)
		return NULL;

	addr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, req.offset);
	if (addr == MAP_FAILED) {
		printf("mmap failed with %s\n", strerror(errno));
		return NULL;
	}

	return addr;
}

static void destroy_bo(int fd, uint32_t handle)
{
	struct amdxdna_ccmd_destroy_bo_req req = {
		.hdr.cmd = AMDXDNA_CCMD_DESTROY_BO,
		.hdr.len = sizeof(req),
		.hdr.rsp_off = 0,
		.handle = handle,
	};
	struct drm_virtgpu_execbuffer exec = {
		.flags = VIRTGPU_EXECBUF_FENCE_FD_OUT | VIRTGPU_EXECBUF_RING_IDX,
		.command = (uint64_t)&req,
		.size = sizeof(req),
		.fence_fd = 0,
		.ring_idx = 1,
	};
	int ret, fence_fd;

	ret = drmIoctl(fd, DRM_IOCTL_VIRTGPU_EXECBUFFER, &exec);
	if (ret < 0) {
		printf("destroy bo cmd failed with %d\n", errno);
	}
	fence_fd = exec.fence_fd;
	sync_wait(fence_fd, -1);
	close(fence_fd);
}

static int create_bo(int fd, uint32_t bo_type, uint32_t res_id, uint64_t size, uint64_t map_align, uint32_t *handle, uint64_t *xdna_addr)
{
	struct amdxdna_ccmd_create_bo_req req = {
		.hdr.cmd = AMDXDNA_CCMD_CREATE_BO,
		.hdr.len = sizeof(req),
		.hdr.rsp_off = 0,
		.res_id = res_id,
		.bo_type = bo_type,
		.size = size,
		.map_align = map_align,
	};
	struct drm_virtgpu_execbuffer exec = {
		.flags = VIRTGPU_EXECBUF_FENCE_FD_OUT | VIRTGPU_EXECBUF_RING_IDX,
		.command = (uint64_t)&req,
		.size = sizeof(req),
		.fence_fd = 0,
		.ring_idx = 1,
	};
	struct amdxdna_ccmd_create_bo_rsp *rsp;
	int fence_fd, ret;

	ret = drmIoctl(fd, DRM_IOCTL_VIRTGPU_EXECBUFFER, &exec);
	if (ret < 0) {
		printf("create bo cmd failed with %d\n", errno);
	}

	fence_fd = exec.fence_fd;
	sync_wait(fence_fd, -1);
	rsp = (struct amdxdna_ccmd_create_bo_rsp *)resp_buf;
	if (xdna_addr)
		*xdna_addr = rsp->xdna_addr;
	if (handle)
		*handle = rsp->handle;
	close(fence_fd);

	return ret;
}

static int create_ctx(int fd, uint32_t *handle)
{
	struct amdxdna_ccmd_create_ctx_req req = {
		.hdr.cmd = AMDXDNA_CCMD_CREATE_CTX,
                .hdr.len = sizeof(req),
                .hdr.rsp_off = 0,
		.max_opc = 2048,
		.num_tiles = 4,
		.qos_info.gops = 100,
	};
	struct drm_virtgpu_execbuffer exec = {
		.flags = VIRTGPU_EXECBUF_FENCE_FD_OUT | VIRTGPU_EXECBUF_RING_IDX,
		.command = (uint64_t)&req,
		.size = sizeof(req),
		.fence_fd = 0,
		.ring_idx = 1,
	};
	struct amdxdna_ccmd_create_ctx_rsp *rsp;
	int fence_fd, ret;

	ret = drmIoctl(fd, DRM_IOCTL_VIRTGPU_EXECBUFFER, &exec);
	if (ret < 0) {
		printf("create ctx cmd failed with %d\n", errno);
	}

	fence_fd = exec.fence_fd;
	sync_wait(fence_fd, -1);
	rsp = (struct amdxdna_ccmd_create_ctx_rsp *)resp_buf;
	*handle = rsp->handle;
	close(fence_fd);

	return ret;
}

int compare(const void *a, const void *b) {
    return strcasecmp(*(const char **)a, *(const char **)b);
}

static int config_ctx(int fd, uint32_t ctx_handle, char *pdi_dir)
{
	struct amdxdna_ccmd_config_ctx_req  *req;
	struct amdxdna_hwctx_param_config_cu *param;
	struct amdxdna_cu_config *cu_conf;
	struct drm_virtgpu_execbuffer exec = { 0 };
	DIR *d = opendir(pdi_dir);
	struct dirent *ent;
	uint32_t i, num_pdi = 0, req_sz;
	char *filenames[32];
	int ret = 0;

	if (!d)
		return -EINVAL;

	while ((ent = readdir(d))) {
		int len = strlen(ent->d_name);

		if (len < 4 || strcmp(ent->d_name + len - 3, "pdi"))
			continue;
		filenames[num_pdi] = strdup(ent->d_name);

		num_pdi++;
	}
	closedir(d);

	qsort(filenames, num_pdi, sizeof(char *), compare);

	req_sz = sizeof(*req) + sizeof(*param) + sizeof(*cu_conf) * num_pdi;
	req = calloc(req_sz, 1);
	param = (struct amdxdna_hwctx_param_config_cu *)req->param_val;
	param->num_cus = num_pdi;
	cu_conf = param->cu_configs;

	for (i = 0; i < num_pdi; i++) {
		FILE *fp;
		uint32_t size, aligned_sz;
		uint64_t xdna_addr;
		void *map_addr;
		char full_name[128];
		uint32_t bo_hdl;

		sprintf(full_name, "%s/%s", pdi_dir, filenames[i]);
		fp = fopen(full_name, "rb");
		if (fp == NULL) {
			printf("failed to open %s\n", full_name);
			return -EFAULT;
		}

		ret = fseek(fp, 0, SEEK_END);
		if (ret) {
			printf("failed to seek\n");
			fclose(fp);
			return ret;
		}

		size = ftell(fp);
		fseek(fp, 0L, SEEK_SET);

		aligned_sz = size + 4095;
		aligned_sz /= 4096;
		aligned_sz *= 4096;

		ret = create_bo(fd, AMDXDNA_BO_DEV, 0, aligned_sz, 0, &bo_hdl, &xdna_addr);
		if (ret) {
			printf("create dev bo failed ret %d\n", ret);
			fclose(fp);
			return ret;
		}

		map_addr = (void *)(heap_addr + xdna_addr - heap_xdna_addr);
		fread(map_addr, size, 1, fp);

		fclose(fp);

		cu_conf[i].cu_bo = bo_hdl;
	}

	req->hdr.cmd = AMDXDNA_CCMD_CONFIG_CTX;
	req->hdr.len = req_sz;
	req->handle = ctx_handle;
	req->param_type = DRM_AMDXDNA_HWCTX_CONFIG_CU;
	req->param_val_size = sizeof(*param) + sizeof(*cu_conf) * num_pdi;

	exec.flags = VIRTGPU_EXECBUF_FENCE_FD_OUT | VIRTGPU_EXECBUF_RING_IDX;
	exec.command = (uint64_t)req;
	exec.size = req_sz;
	exec.ring_idx = 1;

	ret = drmIoctl(fd, DRM_IOCTL_VIRTGPU_EXECBUFFER, &exec);
	if (ret) {
		printf("Config CTX failed ret %d\n", ret);
		return ret;
	}

	return 0;
}

static int
get_capset(int fd, struct virgl_renderer_capset_drm *caps)
{
   struct drm_virtgpu_get_caps args = {
         .cap_set_id = VIRTGPU_DRM_CAPSET_DRM,
         .cap_set_ver = 0,
         .addr = (uintptr_t)caps,
         .size = sizeof(*caps),
   };

   memset(caps, 0, sizeof(*caps));

   return drmIoctl(fd, DRM_IOCTL_VIRTGPU_GET_CAPS, &args);
}

int main(int argc, char *argv[])
{
	struct drm_virtgpu_resource_create_blob mem_blob = { 0 };
	struct amdxdna_ccmd_init_req init_req = {0};
	drmVersionPtr version;
	uint64_t map_addr, xdna_addr;
	uint32_t rsp_bo, rsp_bo_sz;
	uint32_t bo_handle;
	int fd, ret;
	struct drm_virtgpu_execbuffer exec = {
		.flags = VIRTGPU_EXECBUF_FENCE_FD_OUT | VIRTGPU_EXECBUF_RING_IDX,
		.fence_fd = 0,
		.ring_idx = 1,
	};
	struct virgl_renderer_capset_drm caps;

	printf("IOCTL test start\n");

	fd = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) {
		printf("Open device failed\n");
		return fd;
	}

	version = drmGetVersion(fd);
	printf("drm version: %s\n", version->name);

	ret = get_capset(fd, &caps);
	if (ret) {
		printf("Failed to get caps, %d\n", ret);
		return ret;
	}
	printf("Context Type %d\n", caps.context_type);

	set_context(fd);
	printf("set context %d\n", errno);

	/* alloc blob for response */
	mem_blob.size = 4096;
	mem_blob.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
	mem_blob.blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE;
	ret = drmIoctl(fd, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &mem_blob);
	if (ret < 0) {
		printf("Create shmem blob failed %d\n", ret);
		return ret;
	}

	rsp_bo = mem_blob.bo_handle;
	rsp_bo_sz = mem_blob.size;

	init_req.hdr.cmd = AMDXDNA_CCMD_INIT;
	init_req.hdr.len = sizeof(init_req);
	init_req.rsp_res_id = mem_blob.res_handle;

	exec.command = (uint64_t)&init_req;
	exec.size = sizeof(init_req);
	ret = drmIoctl(fd, DRM_IOCTL_VIRTGPU_EXECBUFFER, &exec);
	if (ret < 0) {
		printf("cmd init failed with %d\n", ret);
	}

	mem_blob.size = 1024 * 1024 * 64;
	mem_blob.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
	mem_blob.blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE;
	ret = drmIoctl(fd, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &mem_blob);
	if (ret < 0) {
		printf("DRM_VIRTGPU_RESOURCE_CREATE_BLOB failed with %d\n", ret);
	}

	resp_buf = map_handle(fd, rsp_bo, rsp_bo_sz);
	if (!resp_buf) {
		printf("map response bo failed\n");
		return -ENOMEM;
	}

	ret = create_bo(fd, AMDXDNA_BO_DEV_HEAP, mem_blob.res_handle, mem_blob.size, mem_blob.size, &bo_handle, &heap_xdna_addr);
	if (ret)
		return ret;

	printf("HEAP BO %d MAP xdna addr %lx\n", bo_handle, heap_xdna_addr);
	sleep(1);

	heap_addr = (uint64_t)map_handle(fd, mem_blob.bo_handle, mem_blob.size);
	if (!heap_addr) {
		printf("map heap bo failed\n");
		return -ENOMEM;
	}

	/* dev bo does not have resource. Alloc 4096 from heap bo here */
	ret = create_bo(fd, AMDXDNA_BO_DEV, 0, 4096, 0, NULL, &xdna_addr);
	if (ret)
		return ret;

	printf("DEV BO MAP XDNA addr %lx\n", xdna_addr);
	sleep(1);

	mem_blob.size = 1024;
	mem_blob.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
	mem_blob.blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE;
	ret = drmIoctl(fd, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &mem_blob);
	if (ret < 0) {
		printf("DRM_VIRTGPU_RESOURCE_CREATE_BLOB failed with %d\n", ret);
	}

	ret = create_bo(fd, AMDXDNA_BO_CMD, mem_blob.res_handle, mem_blob.size, 0, &bo_handle, &xdna_addr);
	if (ret)
		return ret;
	printf("COMMAND BO MAP XDNA addr %lx\n", xdna_addr);
	sleep(1);

	destroy_bo(fd, bo_handle);

	mem_blob.size = 1024;
	mem_blob.blob_mem = VIRTGPU_BLOB_MEM_GUEST;
	mem_blob.blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE;
	ret = drmIoctl(fd, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &mem_blob);
	if (ret < 0) {
		printf("DRM_VIRTGPU_RESOURCE_CREATE_BLOB failed with %d\n", ret);
	}

	ret = create_bo(fd, AMDXDNA_BO_SHMEM, mem_blob.res_handle, mem_blob.size, 0, NULL, &xdna_addr);
	if (ret)
		return ret;
	printf("SHARED BO MAP XDNA addr %lx\n", xdna_addr);
	sleep(1);

	uint32_t ctx_handle;
	ret = create_ctx(fd, &ctx_handle);
	if (ret)
		return ret;
	printf("HWCTX %d\n", ctx_handle);
	sleep(1);

	if (argc < 2)
		goto out;

	ret = config_ctx(fd, ctx_handle, argv[1]);
	if (ret) {
		printf("CONFIG CTX failed %d\n", ret);
		return ret;
	}

out:
	close(fd);

	return 0;
}
