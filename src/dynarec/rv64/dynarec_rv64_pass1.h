#define INIT
#define FINI
#define MESSAGE(A, ...) do {} while (0)
#define EMIT(A) do {} while (0)
#define NEW_INST                                          \
    dyn->insts[ninst].f_entry = dyn->f;                   \
    dyn->e.combined1 = dyn->e.combined2 = 0;              \
    for (int i = 0; i < 16; ++i)                          \
        dyn->e.olds[i].v = 0;                             \
    dyn->insts[ninst].vector_sew_entry = dyn->vector_sew; \
    dyn->e.swapped = 0;                                   \
    dyn->e.barrier = 0

#define INST_EPILOG                    \
    dyn->insts[ninst].e = dyn->e;      \
    dyn->insts[ninst].f_exit = dyn->f; \
    dyn->insts[ninst].vector_sew_exit = dyn->vector_sew;

#define INST_NAME(name)
