
cmd:=

all:

cert:
	$(eval cmd:=.tools/bin/cert $(lastword $(MAKECMDGOALS)) && exit 0)
	@chmod +x .tools/bin/cert

serv:
	$(eval cmd:=.tools/bin/serv $(lastword $(MAKECMDGOALS)) && exit 0)
	mkdir -p src/$(lastword $(MAKECMDGOALS))
	@chmod +x .tools/bin/serv

dist:
	$(eval cmd:=.tools/bin/dist $(lastword $(MAKECMDGOALS)) && exit 0)
	@chmod +x .tools/bin/dist

deps:
	$(eval cmd:=.tools/bin/deps $(lastword $(MAKECMDGOALS)) && exit 0)
	@chmod +x .tools/bin/deps

%:
	$(cmd)

clean:

.PHONY: cert serv dist deps
