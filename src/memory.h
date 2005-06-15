

void* _P_;
#define cmalloc(_SIZE_)	 _P_ = malloc(_SIZE_);\
			if(_P_ == NULL) {\
				perror("Not enough memory");\
				exit(0);\
			};

#define cfree(_POINTER_) {if(_POINTER_ != NULL) { \
				free(_POINTER_); \
				_POINTER_ = NULL; \
			  }\
			 else fprintf(stderr, "Warning: You are trying to free a NULL pointer!\n");}



