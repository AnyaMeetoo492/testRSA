default:
	cd "0-SETUP" && make
	cd "1-ALICE" && make
	cd "3-BOB" && make

clean:
	cd "0-SETUP" && make clean
	cd "1-ALICE" && make clean
	cd "3-BOB" && make clean

run:
	cd "0-SETUP" && ./setup
	cd "1-ALICE" && ./alice &
	cd "3-BOB" && ./bob
