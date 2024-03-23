
name:=

%:
	$(eval name:=$@)


print:
	@echo $(name)

.PHONY: print
