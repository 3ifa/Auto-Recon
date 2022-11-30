from flask import *
from flask_cors import CORS
from scanner import *
from urllib.parse import *
import socket


app=Flask(__name__)

CORS(app)



@app.route('/',methods=['POST','GET'])
def form():
    if request.method == 'GET':
        return render_template('index.html')
    if request.method == 'POST':
           target = request.form.get('target')
           args=request.form.get('args')
           return redirect(url_for('scan',target=target))


@app.route('/scan',methods=['POST','GET'])
def scan():
    target =unquote_plus(request.args['target'])
    ip=socket.gethostbyname(target)
    
    try:

        scan__nmap=scannmap(target,'F')
    except:
        scan__nmap="\n"
    
    try:

        ns__enum=ns_enum(target)
    except:
        ns__enum="\n"
    try:

        ip__enum=ip_enum(target)
    except:
        ip__enum="\n"
    try:

        txt__enum=txt_enum(target)
        
    except:
        txt__enum="\n"
    try:

        ipv6__enum=ipv6_enum(target)
        
    except:
        ipv6__enum="\n"
    try:

        mail__enum=mail_enum(target)
        
    except:
        mail__enum="\n"
    try:

        check__waf=checkwaf(target)
        
    except:
        check__waf="\n"
    try:

        basic__Enum=basicEnum(target)
        
    except:
        basic__Enum="\n"
    try:
        cg_enum=cloudgitEnum(target)

        
    except:
        cg_enum="\n"
    
    try:
        whois__lookup=whoisLookup(ip)
    except:
        whois__lookup="\n"
    
    
    return render_template('output.html',scan_nmap=scan__nmap,nsenum=ns__enum,ipenum=ip__enum,txtenum=txt__enum,ipv6enum=ipv6__enum,mailenum=mail__enum,check_waf=check__waf,basic_enum=basic__Enum,cgenum=cg_enum,whois_lookup=whois__lookup)
        
    

    

if __name__ == '__main__' :
    app.run(host="0.0.0.0",port=80,debug=True)