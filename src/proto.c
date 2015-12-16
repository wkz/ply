
#define TYPES(_node_type, _annot_type) (((_node_type) << 8) | (_annot_type))

struct reg *load_left(struct state *s, struct fs_node *n)
{
	struct reg *dst;

	switch (n->type) {
	case FS_BINOP:
		return n->annot->reg;
	case FS_INT:
	case FS_VAR:
	case FS_MAP:
		dst = reg_bind(s, n);
	default:
		assert(1);
	}

	switch (n->type) {
	case FS_INT:
		emit(s, MOV_IMM(dst->reg, n->integer));
		

int compile_post(struct fs_node *n, void *_probe)
{
	struct fs_node *probe = _probe;
	struct location *a, *b;
	int err;

	switch (TYPES(n->type, n->annot.type)) {
	case TYPES(FS_PRED, FS_INT):
		a = locate_int(n->pred.left);
		b = locate_int(n->pred.right);
		emit_cmp(
		
}

int compile(struct fs_node *probe)
{
	return fs_walk(probe, probe, NULL, compile_post, probe);
}
