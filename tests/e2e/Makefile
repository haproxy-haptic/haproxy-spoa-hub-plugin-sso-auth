.PHONY: e2e e2e-clean

e2e:
	./run.sh

e2e-clean:
	kind delete clusters --filter 'e2e-sso-auth-*' 2>/dev/null || true
