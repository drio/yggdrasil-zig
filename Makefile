ED25519_PUBLIC_KEY=6ZGsimui1bR5zq0bK6uWg6KQqTID+OZJzPR/c24iV54= 
ED25519_SECRET_KEY=HWt4/m8UGNCYzNIzCBaFLoBbe2K/Y+q/dCZSi1zSp9zpkayKa6LVtHnOrRsrq5aDopCpMgP45knM9H9zbiJXng== 
Z=/home/drio/zigs/zig/zig

test:
	$(Z) run ./test.zig

run:
	ED25519_PUBLIC_KEY=$(ED25519_PUBLIC_KEY) \
	ED25519_SECRET_KEY=$(ED25519_SECRET_KEY) \
	$(Z) run src/main.zig

run/sudo:
	ED25519_PUBLIC_KEY=$(ED25519_PUBLIC_KEY) \
	ED25519_SECRET_KEY=$(ED25519_SECRET_KEY) \
	sudo -E env $(Z) run src/main.zig

tun/delete:
	sudo ip link delete tun0

tun/check/4:
	ip addr show tun0
	@echo
	ip route

tun/check/6:
	ip -6 addr show tun0
	@echo
	ip -6 route

