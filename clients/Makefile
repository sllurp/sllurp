CLIENTS = reader_test simple_inventory

clean:
	$(foreach client,$(CLIENTS),$(MAKE) -C $(client) $@ && ) true

.PHONY: clean
