

pktweak:
	go build -buildmode=plugin -o pktweak.so plugin/pktweak.go


clean:
	rm -f pktweak.so