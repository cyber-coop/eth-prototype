postgres:
	docker run --name prototype-postgres -e POSTGRES_PASSWORD=wow -e POSTGRES_DB=blockchains -p 5432:5432 -d postgres

run:
	RUST_LOG="eth_prototype=info" cargo r -- $(network)