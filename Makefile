postgres:
	docker run --name prototype-postgres -v ./contrib/docker-entrypoint-initdb.d:/docker-entrypoint-initdb.d -e POSTGRES_PASSWORD=wow -e POSTGRES_DB=blockchains -p 5432:5432 -d postgres

run:
	RUST_LOG="eth_prototype=trace" cargo r -- $(network)

azimutt:
	docker run -d --name azimutt --env-file ./contrib/azimutt.env --network host ghcr.io/azimuttapp/azimutt:main