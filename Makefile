.PHONY: all build clean su sd client check cover scp lint docker help
BIN_FILE=ktun

all: check build
build:
	@go build -o "${BIN_FILE}"
clean: sd
	@go clean
	rm -f ${BIN_FILE}
test:
	@go test
check:
	@go fmt ./
	@go vet ./
cover:
	@go test -coverprofile ${BIN_FILE}.out
	@go tool cover -html=${BIN_FILE}.out
scp: check build
	scp ${BIN_FILE} ubuntu@oarmt:~
	scp ${BIN_FILE} ubuntu@oarmk1:~
su: check build
	./${BIN_FILE} server up -d
sd:
	./${BIN_FILE} server down
client: check build
	./${BIN_FILE} client
docker:
	@docker build -t nucuriel/${BIN_FILE}:latest .
help:
	@echo "make 格式化go代码 并编译生成二进制文件"
	@echo "make build 编译go代码生成二进制文件"
	@echo "make clean 清理中间目标文件"
	@echo "make test 执行测试case"
	@echo "make check 格式化go代码"
	@echo "make cover 检查测试覆盖率"
	@echo "make su 启动服务端"
	@echo "make sd 停止服务端"
	@echo "make client 启动客户端"
	@echo "make docker 构建docker镜像"