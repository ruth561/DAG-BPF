// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bpf.h>

#include "dag_bpf.h"

MODULE_AUTHOR("Takumi Jin");
MODULE_DESCRIPTION("A simple implementation of a kernel module using struct_ops");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("0.1");

// MARK: my_ops
struct my_ops {
	int (*calculate)(int n);
};

static struct my_ops gops;

static bool my_ops_is_valid_access(int off, int size,
				   enum bpf_access_type type,
				   const struct bpf_prog *prog,
				   struct bpf_insn_access_aux *info)
{
	if (off == 0 && size == sizeof(u64))
		return true;
	return false;
}

static const struct bpf_func_proto *my_ops_get_func_proto(enum bpf_func_id func_id,
							  const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static struct bpf_verifier_ops my_ops_bpf_verifier_ops = {
	.get_func_proto  = my_ops_get_func_proto,
	.is_valid_access = my_ops_is_valid_access,
};

static int bpf_my_ops_init(struct btf *btf)
{
	pr_info("st_ops->init()\n");

	return 0;
}

static int bpf_my_ops_init_member(const struct btf_type *t,
				  const struct btf_member *member,
				  void *kdata, const void *udata)
{
	pr_info("st_ops->init_member()\n");

	return 0;
}

static int bpf_my_ops_check_member(const struct btf_type *t,
				   const struct btf_member *member,
				   const struct bpf_prog *prog)
{
	pr_info("st_ops->check_member()\n");

	if (prog->sleepable)
		return -EINVAL;
	return 0;
}

static int bpf_my_ops_reg(void *kdata, struct bpf_link *link)
{
	pr_info("st_ops->reg()\n");

	gops = *(struct my_ops *) kdata;
	return 0;
}

static void bpf_my_ops_unreg(void *kdata, struct bpf_link *link)
{
	pr_info("st_ops->unreg()\n");
	gops.calculate = NULL;
}

static int calculate_stub(int n)
{
	return n;
}

static struct my_ops my_ops_stubs = {
	.calculate = calculate_stub,
};

static struct bpf_struct_ops bpf_my_ops = {
	.verifier_ops	= &my_ops_bpf_verifier_ops,
	.init		= bpf_my_ops_init,
	.init_member	= bpf_my_ops_init_member,
	.check_member	= bpf_my_ops_check_member,
	.reg		= bpf_my_ops_reg,
	.unreg		= bpf_my_ops_unreg,
	.name		= "my_ops",
	.owner		= THIS_MODULE,
	.cfi_stubs	= &my_ops_stubs,
};

// MARK: kfuncs
__bpf_kfunc_start_defs();

/**
 * msg:
 *
 * return value: dag_task id if succeeded, otherwise -1.
 */
__bpf_kfunc struct bpf_dag_task *bpf_dag_task_alloc(u8 *msg, u32 size)
{
	// TODO:
	pr_info("bpf_dag_task_alloc\n");
	return NULL;
}

__bpf_kfunc void bpf_dag_task_dump(s32 dag_task_id)
{
	pr_info("[*] bpf_graph_dump\n");
	// TODO:
}

/**
 * return value: 0 if succeeded, -1 if failed.
 */
__bpf_kfunc s32 bpf_dag_task_free(struct bpf_dag_task *dag_task)
{
	pr_info("[*] bpf_dag_task_free\n");
	// TODO:
	return -1;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(my_ops_kfunc_ids)
BTF_ID_FLAGS(func, bpf_dag_task_alloc, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_dag_task_free, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_dag_task_dump)
BTF_KFUNCS_END(my_ops_kfunc_ids)

static const struct btf_kfunc_id_set my_ops_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &my_ops_kfunc_ids,
};

// =============================================================================
// The following implementations are for files in sysfs:my_ops.
// =============================================================================
static int n = 0;

static ssize_t ctl_show(struct kobject *kobj, struct kobj_attribute *attr,
                        char *buf)
{
	int val;

	if (gops.calculate) {
		val = gops.calculate(n);
	} else {
		pr_info("ops.calculate is NULL...\n");
		val = n;
	}

	return sprintf(buf, "ctl_show: val=%d\n", val);
}

static ssize_t ctl_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	int ret;

	ret = kstrtoint(buf, 10, &n);
	if (ret < 0) {
		pr_err("failed to convert buf to int\n");
		return ret;
	}

	pr_info("ctl_store: n=%d\n", n);
	return count;
}

// sysfs:my_ops dir
static struct kobject *my_ops_kobj;
// sysfs:my_ops/ctl file
static struct kobj_attribute ctl_attr = __ATTR(ctl, 0660, ctl_show, ctl_store);

static int __init my_ops_init(void)
{
	int err;

	pr_info("my_ops_init\n");

	memset(&gops, 0, sizeof(struct my_ops));

	my_ops_kobj = kobject_create_and_add("my_ops", kernel_kobj);
	if (!my_ops_kobj) {
		pr_err("failed to create and add my_ops kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_file(my_ops_kobj, &ctl_attr.attr);
	if (err) {
		pr_err("failed to create file sysfs:my_ops/ctl\n");
		return err;
	}

	// bpf_graph_manager_init();

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &my_ops_kfunc_set);
	if (err) {
		pr_err("failed to register kfuncs (%d)\n", err);
		return err;
	}

	err = register_bpf_struct_ops(&bpf_my_ops, my_ops);
	if (err) {
		pr_err("failed to register struct_ops my_ops\n");
		return err;
	}

	return 0;
}

static void __exit my_ops_exit(void)
{
	pr_info("my_ops_exit\n");

	kobject_put(my_ops_kobj);
}

module_init(my_ops_init);
module_exit(my_ops_exit);
