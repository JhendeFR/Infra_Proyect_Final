Para este proyecto se utilizaron 4 entornos:
- Proxy     192.168.100.1/24
- WebApp  192.168.100.20
- DB     192.168.100.30
- Storage    192.168.100.40
# Configuraciones Netplan
Acceder al archivo de configuración:
```
sudo nano /etc/netplan/00-installer-config.yaml
```
Configurar (Proxy):
```
network:
  version: 2
  ethernets:
    enp0s3:   # NAT
      dhcp4: false
      optional: true
      addresses:
        - 10.0.2.15/24
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      routes:
        - to: 0.0.0.0/0
          via: 10.0.2.2
    enp0s8:   # Red interna
      dhcp4: false
      optional: true
      addresses:
        - 192.168.100.1/2
```
WebApp:
```
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
    enp0s8:
      dhcp4: false
      addresses:
        - 192.168.100.20/24
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      routes:
        - to: 0.0.0.0/0
          via: 192.168.100.1
```
DB:
```
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
    enp0s8:
      dhcp4: false
      addresses:
        - 192.168.100.30/24
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      routes:
        - to: 0.0.0.0/0
          via: 192.168.100.1
```
Storage:
```
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
    enp0s8:
      dhcp4: false
      addresses:
        - 192.168.100.40/24
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      routes:
        - to: 0.0.0.0/0
          via: 192.168.100.1
```
Validar y aplicar:
```
sudo netplan generate
sudo netplan apply
```
# Configuración de Port Forwarding en VirtualBox (temporal para el acceso mediante ssh)
En este apartado configuraremos las reglas para el adaptador 1 en NAT de las VM's de manera temporal solo para facilitarnos la configuración mediante ssh de las mismas:

| Nombre      | Protocolo | IP anfitrión | Puerto anfitrión | IP invitado    | Puerto invitado |
| ----------- | --------- | ------------ | ---------------- | -------------- | --------------- |
| SSH-Proxy   | TCP       |              | 2222             | 10.0.2.15      | 22              |
| SSH-WebApp  | TCP       |              | 2223             | 192.168.100.20 | 22              |
| SSH-DB      | TCP       |              | 2224             | 192.168.100.30 | 22              |
| SSH-Storage | TCP       |              | 2225             | 192.168.100.40 | 22              |
## Habilitar NAT + Forwarding en el Proxy
Habilitar forwarding temporalmente
```
sudo sysctl -w net.ipv4.ip_forward=1
```
Configurar las NAT's con iptables
```
# Enmascarar tráfico de la red interna hacia internet
sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o enp0s3 -j MASQUERADE

# Permitir forwarding de enp0s8 → enp0s3
sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT

# Permitir tráfico de retorno enp0s3 → enp0s8
sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT
```
Hacerlo persistente
```
sudo nano /etc/sysctl.conf
```
Dentro de ese archivo descomentar o colocar:
```
net.ipv4.ip_forward=1
```
Aplicar
```
sudo sysctl -p
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```
De esta manera desde la pc host logramos acceder con warp a las vms de la siguiente manera:
```
ssh Jherson@127.0.0.1 -p 2222
ssh Jherson@127.0.0.1 -p 2223
ssh Jherson@127.0.0.1 -p 2224
ssh Jherson@127.0.0.1 -p 2225
```
# Proxy y balanceador de carga
Instalar Ngnix
```
sudo apt install -y nginx
```
Verificación
```
systemctl status nginx
sudo systemctl enable nginx
```
## Configuración de reverse proxy hacia WebApp
Crear archivo para el sitio
```
sudo nano /etc/nginx/sites-available/photos-proxy.conf
```
[^1]Contenido recomendado:
```
upstream webapp_backend {
    # Punto único (luego agregamos más para balanceo)
    server 192.168.100.20:8000 max_fails=3 fail_timeout=10s;
    # Si escalas, agrega más:
    # server 192.168.100.21:8000;
    # server 192.168.100.22:8000;
}
server {
    listen 80;
    server_name _;

    # Logs (útiles para tu defensa y troubleshooting)
    access_log /var/log/nginx/photos_access.log;
    error_log  /var/log/nginx/photos_error.log warn;

    # Seguridad y cabeceras básicas
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
   # client_max_body_size 50MB; esto habilitar si es necesario despues

    # Proxy hacia la WebApp
    location / {
        proxy_pass http://webapp_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }
    # Estático opcional servido desde Proxy (si decides cache local)
    # location /static/ {
    #     root /srv/photos-proxy;
    #     try_files $uri =404;
    # }
    # Proxy de archivos al servidor Storage
    location /files/ {
        # Importante: usa la barra final en ambos lados para mantener rutas correctas
        proxy_pass http://192.168.100.40/files/;

        # Cabeceras útiles
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }

```
Desactivar el sitio por defecto
```
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```
Activar el sitio y verficar
```
sudo ln -s /etc/nginx/sites-available/photos-proxy.conf /etc/nginx/sites-enabled/photos-proxy.conf
sudo nginx -t
sudo systemctl reload nginx
```
## Port forwarding para acceder desde el host (configurar en el Proxy)

| Nombre | Protocolo | IP anfitrión | Puerto anfitrión | IP invitado | Puerto invitado |
| ------ | --------- | ------------ | ---------------- | ----------- | --------------- |
| HTTP   | TCP       |              | 8080             | 10.0.2.15   | 80              |
Con esto deberíamos tener configurado el Proxy para escuchar el servicio de WebApp desde el puerto 8080, lo validaremos al configurar WebApp
[^1]: Recomendado para balanceo de carga
	upstream webapp_backend {
	    least_conn; # estrategia de balanceo recomendada
	    server 192.168.100.20:8000 max_fails=3 fail_timeout=10s;
	    server 192.168.100.21:8000 max_fails=3 fail_timeout=10s;
	    server 192.168.100.22:8000 max_fails=3 fail_timeout=10s;
	}
# WebApp
## Instalación y configuración de Flask
Instalar y verifica
```
sudo apt install -y python3-flask
sudo apt install -y python3-pymysql python3-flask-bcrypt
python3 -m flask --version
```
Crear la aplicación
```
nano app.py
```
Contenido
```
from flask import Flask, request, redirect, url_for, render_template_string, session
import pymysql
from flask_bcrypt import Bcrypt
import requests

app = Flask(__name__)
app.secret_key = "SuperSecretKey"  # cámbialo en producción
bcrypt = Bcrypt(app)

# Configuración DB
db_config = {
    "host": "192.168.100.30",
    "user": "photos_user",
    "password": "Str0ng_Pass!",
    "database": "photos_db"
}
# Plantillas simples
login_page = """
<h2>Login</h2>
<form method="POST">
  Email: <input type="text" name="email"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
<a href="/register">Register</a>
"""

register_page = """
<h2>Register</h2>
<form method="POST">
  Email: <input type="text" name="email"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Register">
</form>
<a href="/login">Login</a>
"""
upload_page = """
<h2>Upload Photo</h2>
<form method="POST" enctype="multipart/form-data">
  <input type="file" name="photo"><br>
  <input type="submit" value="Upload">
</form>
<a href="/photos">My Photos</a>
"""
@app.route("/")
def home():
    if "user_id" in session:
        return f"Welcome {session['email']}! <br><a href='/upload'>Upload Photo</a> | <a href='/photos'>>
    return "<a href='/login'>Login</a> | <a href='/register'>Register</a>"

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")
        conn = pymysql.connect(**db_config)
        cur = conn.cursor()
        cur.execute("INSERT INTO users (email, password_hash) VALUES (%s,%s)", (email,password))
        conn.commit()
        conn.close()
        return redirect(url_for("login"))
    return render_template_string(register_page)
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        conn = pymysql.connect(**db_config)
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        conn.close()
        if user and bcrypt.check_password_hash(user[1], password):
            session["user_id"] = user[0]
            session["email"] = email
            return redirect(url_for("home"))
    return render_template_string(login_page)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))
@app.route("/upload", methods=["GET","POST"])
def upload():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        photo = request.files["photo"]
        filename = photo.filename

        # Enviar al Storage vía PUT
        storage_url = f"http://192.168.100.40/upload/uploads/{filename}"
        r = requests.put(storage_url, data=photo.stream)

        if r.status_code in [200,201]:
            # Registrar en BD
            conn = pymysql.connect(**db_config)
            cur = conn.cursor()
            cur.execute("INSERT INTO photos (user_id, filename, storage_path) VALUES (%s,%s,%s)",
                        (session["user_id"], filename, f"/files/{filename}"))
            conn.commit()
            conn.close()
            return redirect(url_for("photos"))
        else:
            return f"Error uploading file: {r.status_code}"
    return render_template_string(upload_page)
@app.route("/photos")
def photos():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = pymysql.connect(**db_config)
    cur = conn.cursor()
    cur.execute("SELECT filename FROM photos WHERE user_id=%s", (session["user_id"],))
    rows = cur.fetchall()
    conn.close()
    links = "".join([f"<li><a href='/files/{r[0]}'>{r[0]}</a></li>" for r in rows])
    return f"<h2>My Photos</h2><ul>{links}</ul><a href='/upload'>Upload more</a>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
```
Ejecutar (Al tener ya listo DB y Storage)
```
python3 app.py
```
# Base de datos en la VM DB
Instalar
```
sudo apt install -y mariadb-server
sudo mysql_secure_installation
```
Configurar
```
Switch to unix_socket authentication [Y/n]   Y [Enter]
Change the root password? [Y/n]    n [Enter]
```
Crear Base de datos, usuarios y esquemas
```
sudo mysql
```
Usuario
```
CREATE DATABASE photos_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'photos_user'@'192.168.100.%' IDENTIFIED BY 'Str0ng_Pass!';

GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, ALTER
  ON photos_db.* TO 'photos_user'@'192.168.100.%';

FLUSH PRIVILEGES;
```
Tablas
```
USE photos_db;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(190) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE photos (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  filename VARCHAR(255) NOT NULL,
  storage_path VARCHAR(255) NOT NULL,
  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```
Verificación en WebApp
```
sudo apt install -y mariadb-client
mysql -h 192.168.100.30 -u photos_user -p photos_db -e "SHOW TABLES;"
```
Debería pedir la contraseña (`Str0ng_Pass!`) y mostrar las tablas
# Storage
Instalar Ngnix
```
sudo apt install -y nginx
systemctl status nginx
 # Si no esta activo, activarlo:
sudo systemctl enable nginx
sudo systemctl start nginx
```
Crear la carpeta de almacenamiento
```
sudo mkdir -p /srv/photos/uploads
sudo chown -R www-data:www-data /srv/photos
sudo chmod -R 750 /srv/photos
```
Configuramos ngnix para servir archivos
```
sudo nano /etc/nginx/sites-available/photos-storage.conf
```
Contenido
```
server {
    listen 80;
    server_name _;

    access_log /var/log/nginx/storage_access.log;
    error_log  /var/log/nginx/storage_error.log warn;

    # Endpoint de salud
    location /health {
        return 200 'OK';
        add_header Content-Type text/plain;
    }

    # Servir archivos desde /srv/photos/uploads
    location /files/ {
        alias /srv/photos/uploads/;
        autoindex on;
        add_header X-Served-By storage always;
    }
   # Endpoint para subir archivos
   location /upload {
       client_max_body_size 50M;   # límite por archivo
       root /srv/photos;
       dav_methods PUT;            # habilita método PUT
       create_full_put_path on;    # crea carpetas si no existen
   }
}
```
Desactivar el sitio por defecto
```
sudo ln -s /etc/nginx/sites-available/photos-storage.conf /etc/nginx/sites-enabled/photos-storage.conf
sudo rm /etc/nginx/sites-enabled/default
```
Recargar Ngnix
```
sudo nginx -t
sudo systemctl reload nginx
```
## Exponer Storage a través del Proxy
Esto ya deberia estar gracias a las configuraciones directas en los pasos anteriores
### Resumen
Con toda esta configuración esta funcionando el sistema accediendo desde el host se puede registrar, logear, subir imagenes y ver sus imagenes. (al iniciar las vms deben ejecutar ```python3 app.py``` ) e ingresar a http://localhost:8080/login en el navegador de la maquina host

| Componente    | Tecnología                                | Rol                                                                                              |
| ------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Proxy         | Nginx                                     | Balanceo de carga, reverse proxy, seguridad                                                      |
| WebApp        | **Flask (Python)** + **bcrypt** + PyMySQL | Lógica de negocio: login, subida, listado                                                        |
| DB            | MariaDB                                   | Persistencia de usuarios y metadatos                                                             |
| Storage       | Nginx (con DAV/PUT)                       | Almacenamiento y servicio de archivos                                                            |
| Seguridad     | UFW, HTTPS (Nginx)                        | Control de acceso y cifrado (Requerimento pedido por el ingeniero que nos falta habilitar)       |
| Interfaz      | Html+CSS                                  | Nos falta implementar para una mejor UX                                                          |
| Accesibilidad | Router                                    | Nos falta exponer para todos los dispositivos que estén en la misma red wifi que la maquina host |
| SSH Jump Host |                                           |                                                                                                  |
## 2da vuelta
En esta parte terminare la configuracion de las vms listas para la presentacion final:
### SSH Jump Host (arreglando lo anterior de PortForwarding)
Quitaremos el adaptador NAT de las vms (excepto de Proxy) por que el Proxy les dara una salida a internet y también conexión mediante ssh, para eso deberás editar ```/etc/netplan/00-installer-config.yaml```, en el bloque enp0s3 colocar ```optional: true``` y por ultimo aplicar
```
sudo netplan apply
```
Instalar tablas de persistencia:
```
sudo apt install iptables-persistent
```
Editar
```
sudo nano /etc/sysctl.conf
```
Buscar la linea ```net.ipv4.ip_forward=1```  y quitarle el ```#``` o simplemente escribirla al final, guardar y salir.
Recargar la configuracion
```
sudo sysctl -p
```
Configurar enmascaramiento
```
# 1. Enmascarar tráfico saliente (La clave para tener internet)
# Todo lo que venga de 192.168.100.0/24 y salga por enp0s3, llevará la IP del Proxy
sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o enp0s3 -j MASQUERADE

# 2. Permitir el paso desde la red interna hacia internet
sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT

# 3. Permitir que la respuesta de internet regrese a la red interna
sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT
# 4. Guardar las reglas
sudo netfilter-persistent save
```
Ahora con esto ya deberiamos tener internet en las vms mediante el proxy lo puedes comprobar con ```ping -c 4 8.8.8.8``` en cada vm y para acceder por ssh a las vms deberas primero acceder al proxy y luego a las vms de la siguiente manera

| VM      | Acceso                              |
| ------- | ----------------------------------- |
| Proxy   | ```ssh Jherson@127.0.0.1 -p 2222``` |
| WebApp  | ```ssh Jherson@192.168.100.20```    |
| DB      | ```ssh Jherson@192.168.100.30```    |
| Storage | ```ssh Jherson@192.168.100.40```    |
### Hardening de SSH
En cada VM edita `sudo nano /etc/ssh/sshd_config` -> Cambiar a `Port 2222` y `PermitRootLogin no` -> `sudo systemctl restart ssh` -> ```sudo shutdown -p now``` (Esto es mi forma de apagar de forma segura si no se te joden las vms apaga de la manera que quieras).

Adicionalmente deberemos configurar en el proxy:
- Configuración de Proxy -> Red -> Adaptador 1 (NAT) -> Reenvío de puertos.
- Edita la regla SSH-Proxy: Cambia el **Puerto Invitado** de `22` a `2222`
Inicia las vms y prueba la conexión a cada una de la siguiente manera:

| VM      | Acceso                                   |
| ------- | ---------------------------------------- |
| Proxy   | ```ssh Jherson@127.0.0.1 -p 2222```      |
| WebApp  | ```ssh Jherson@192.168.100.20 -p 2222``` |
| DB      | ```ssh Jherson@192.168.100.30 -p 2222``` |
| Storage | ```ssh Jherson@192.168.100.40 -p 2222``` |
### Firewall UFW
Instalar ufw
```
sudo apt install ufw
```
El Proxy necesita recibir tráfico de internet (Host) y permitir SSH
```
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Permitir SSH (Nuevo puerto)
sudo ufw allow 2222/tcp

# Permitir Trafico Web y SSL
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Permitir trafico de la red interna (para que vuelvan las respuestas de las VMs)
sudo ufw allow from 192.168.100.0/24 to any

sudo ufw enable
```
Solo acepta SSH del Proxy y tráfico HTTP del Proxy
```
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Solo SSH desde Proxy
sudo ufw allow from 192.168.100.1 to any port 2222

# Solo tráfico Flask (8000) desde Proxy
sudo ufw allow from 192.168.100.1 to any port 8000

sudo ufw enable
```
Solo acepta SSH del Proxy y Consultas SQL de WebApp
```
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Solo SSH desde Proxy
sudo ufw allow from 192.168.100.1 to any port 2222

# Solo MySQL desde WebApp
sudo ufw allow from 192.168.100.20 to any port 3306

sudo ufw enable
```
Este es especial: Recibe archivos de WebApp (upload) y sirve archivos al Proxy (lectura)
```
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Solo SSH desde Proxy
sudo ufw allow from 192.168.100.1 to any port 2222

# Nginx (Puerto 80): Permitir acceso desde Proxy (para servir) y WebApp (para subir)
sudo ufw allow from 192.168.100.1 to any port 80
sudo ufw allow from 192.168.100.20 to any port 80

sudo ufw enable
```
### Hardening de Nginx y SSL (Solo Proxy)
Esto en la vm del proxy
```
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout /etc/nginx/ssl/nginx-selfsigned.key \
-out /etc/nginx/ssl/nginx-selfsigned.crt
# (Te pedira datos basicos como pais, estado, ciudad, nombre y correo)
```
Editar ```sudo nano /etc/nginx/nginx.conf``` en el bloque http:
```
server_tokens off;             # Ocultar versión de Nginx
ssl_session_cache shared:SSL:10m;

# Rate Limiting (Protección DDoS)
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=5r/s;
```
Para la configuración de Https vamos a modificar el archivo de configuración del proxy: `sudo nano /etc/nginx/sites-available/photos-proxy.conf`:
```
upstream webapp_backend {
    server 192.168.100.20:8000 max_fails=3 fail_timeout=10s;
}

# Redirección de HTTP a HTTPS
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

# Servidor Principal HTTPS
server {
    listen 443 ssl;
    server_name _;

    # Certificados
    ssl_certificate /etc/nginx/ssl/nginx-selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx-selfsigned.key;

    # Hardening TLS (Según Lab)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';

    # Cabeceras de Seguridad
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";

    # Logs
    access_log /var/log/nginx/photos_access.log;
    error_log  /var/log/nginx/photos_error.log warn;

    # Protección de Rate Limiting (Aplicado aquí)
    limit_req zone=api_limit burst=10 nodelay;

    # Proxy a WebApp
    location / {
        proxy_pass http://webapp_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Proxy a Storage
    location /files/ {
        proxy_pass http://192.168.100.40/files/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
Verificar y reiniciar:
```
sudo nginx -t
sudo systemctl restart nginx
```
Ahora cambiaremos la regla Http (yo directamente modifique para no tener activo http pero puedes crear otra regla exclusiva para https) de portforwarding en virtual box:

| Nombre | Protocolo | IP anfitrión | Puerto anfitrión | IP invitado | Puerto invitado |
| ------ | --------- | ------------ | ---------------- | ----------- | --------------- |
| HTTP   | TCP       |              | 8443             | 10.0.2.15   | 443             |
Ahora en al correr la app desde WebApp ya deberia estar funcionando la pagina en ```https://localhost:8443/```
### Liberar para los dispositivos de la misma red wifi que e host
Para la demostración y funcionalidad quisimos exponer el proyecto para su uso masivo en dispositivos que se encuentren en la misma red que el host, para eso debemos configurar el firewall de Windows:
- Presiona la tecla Windows y escribe **"Firewall de Windows Defender con seguridad avanzada"**.
    
- En el panel izquierdo, selecciona **Reglas de entrada** (Inbound Rules).
    
- En el panel derecho, haz clic en **Nueva regla...**.
    
- Selecciona **Puerto** -> Siguiente.
    
- Selecciona **TCP** y en "Puertos locales específicos" escribe: `8443` (o el puerto que estés usando para HTTPS).
    
- Selecciona **Permitir la conexión**.
    
- Marca todas las casillas (Dominio, Privado, Público) -> Siguiente.
    
- Ponle un nombre, ej: `InfraProyect -> Finalizar.
Prueba desde el celular:
Para eso debemos saber la ip de nuestro host en nuestro caso es 192.168.100.103 (pero puede cambiar por dhcp)
Escribir en el navegador del otro dispositivo:
`https://192.168.100.103:8443/`
## Fronted y mejora de UX en la pagina
Crear la estructura de directorios
```
mkdir templates
cd templates
```
Crea el archivo `templates/base.html`:
```
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhotoBackup</title>
    <style>
        :root {
            --primary: #2563eb;
            --bg: #f8fafc;
            --surface: #ffffff;
            --text: #1e293b;
            --border: #e2e8f0;
        }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        nav {
            background: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        nav a {
            text-decoration: none;
            color: var(--text);
            margin-left: 1.5rem;
            font-weight: 500;
        }
        nav a:hover { color: var(--primary); }
        .brand { font-weight: bold; font-size: 1.2rem; color: var(--primary); }
        
        main {
            flex: 1;
            padding: 2rem;
            max-width: 1000px;
            margin: 0 auto;
            width: 100%;
        }
        
        /* Formularios y Tarjetas */
        .card {
            background: var(--surface);
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            max-width: 400px;
            margin: 2rem auto;
        }
        input[type="text"], input[type="password"], input[type="file"] {
            width: 100%;
            padding: 0.75rem;
            margin-bottom: 1rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            box-sizing: border-box; /* Importante para padding */
        }
        button, input[type="submit"] {
            background-color: var(--primary);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            cursor: pointer;
            width: 100%;
            font-weight: bold;
        }
        button:hover, input[type="submit"]:hover { opacity: 0.9; }
        
        /* Galería de Fotos (Grid) */
        .gallery {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 1.5rem;
        }
        .photo-card {
            background: var(--surface);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .photo-card:hover { transform: translateY(-4px); }
        .photo-card img {
            width: 100%;
            height: 200px;
            object-fit: cover;
            display: block;
        }
        .photo-info { padding: 0.8rem; font-size: 0.9rem; text-align: center; }
    </style>
</head>
<body>
    <nav>
        <div class="brand">☁️ PhotoBackup</div>
        <div>
            {% if session.user_id %}
                <a href="/photos">Mis Fotos</a>
                <a href="/upload">Subir</a>
                <a href="/logout" style="color: #ef4444;">Salir</a>
            {% else %}
                <a href="/login">Entrar</a>
                <a href="/register">Registro</a>
            {% endif %}
        </div>
    </nav>
    <main>
        {% block content %}{% endblock %}
    </main>
</body>
</html>
```
`templates/login.html`:
```
{% extends "base.html" %}
{% block content %}
<div class="card">
    <h2 style="text-align: center;">Iniciar Sesión</h2>
    <form method="POST">
        <label>Email</label>
        <input type="text" name="email" required placeholder="tu@email.com">
        
        <label>Contraseña</label>
        <input type="password" name="password" required>
        
        <input type="submit" value="Entrar">
    </form>
    <p style="text-align: center; margin-top: 1rem;">
        <a href="/register">¿No tienes cuenta? Regístrate</a>
    </p>
</div>
{% endblock %}
```
`templates/register.html`:
```
{% extends "base.html" %}
{% block content %}
<div class="card">
    <h2 style="text-align: center;">Crear Cuenta</h2>
    <form method="POST">
        <label>Email</label>
        <input type="text" name="email" required placeholder="tu@email.com">
        
        <label>Contraseña</label>
        <input type="password" name="password" required>
        
        <input type="submit" value="Registrarse">
    </form>
</div>
{% endblock %}
```
`templates/upload.html`:
```
{% extends "base.html" %}
{% block content %}
<div class="card">
    <h2 style="text-align: center;">Subir Foto</h2>
    <form method="POST" enctype="multipart/form-data">
        <div style="border: 2px dashed #cbd5e1; padding: 2rem; text-align: center; margin-bottom: 1rem; border-radius: 8px;">
            <input type="file" name="photo" required>
        </div>
        <input type="submit" value="Subir a la Nube">
    </form>
</div>
{% endblock %}
```
`templates/photos.html`:
```
{% extends "base.html" %}
{% block content %}
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
    <h2>Mi Galería</h2>
    <a href="/upload" style="background: var(--primary); color: white; padding: 0.5rem 1rem; text-decoration: none; border-radius: 6px;">+ Nueva Foto</a>
</div>

{% if photos %}
    <div class="gallery">
        {% for photo in photos %}
        <div class="photo-card">
            <a href="/files/{{ photo[0] }}" target="_blank">
                <img src="/files/{{ photo[0] }}" alt="{{ photo[0] }}" loading="lazy">
            </a>
            <div class="photo-info">{{ photo[0] }}</div>
        </div>
        {% endfor %}
    </div>
{% else %}
    <div style="text-align: center; color: #64748b; margin-top: 3rem;">
        <p>No tienes fotos aún.</p>
        <a href="/upload">¡Sube la primera!</a>
    </div>
{% endif %}
{% endblock %}
```
Actualizar `app.py`:
```
from flask import Flask, request, redirect, url_for, render_template, session
import pymysql
from flask_bcrypt import Bcrypt
import requests

app = Flask(__name__)
app.secret_key = "SuperSecretKey"
bcrypt = Bcrypt(app)

# Configuración DB
db_config = {
    "host": "192.168.100.30",
    "user": "photos_user",
    "password": "Str0ng_Pass!",
    "database": "photos_db"
}

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("photos"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        # Encriptación simple
        password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")
        
        conn = pymysql.connect(**db_config)
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (email, password_hash) VALUES (%s,%s)", (email,password))
            conn.commit()
        except Exception as e:
            return f"Error: {e}" # Manejo básico de error (ej. email duplicado)
        finally:
            conn.close()
            
        return redirect(url_for("login"))
    return render_template("register.html", session=session)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        
        conn = pymysql.connect(**db_config)
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user[1], password):
            session["user_id"] = user[0]
            session["email"] = email
            return redirect(url_for("photos"))
        else:
            return render_template("login.html", error="Credenciales inválidas")
            
    return render_template("login.html", session=session)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/upload", methods=["GET","POST"])
def upload():
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    if request.method == "POST":
        if 'photo' not in request.files:
            return "No file part"
            
        photo = request.files["photo"]
        if photo.filename == '':
            return "No selected file"
            
        filename = photo.filename

        # Enviar al Storage vía PUT
        storage_url = f"http://192.168.100.40/upload/uploads/{filename}"
        
        try:
            r = requests.put(storage_url, data=photo.stream)
            
            if r.status_code in [200, 201, 204]:
                # Registrar en BD solo si se guardó en Storage
                conn = pymysql.connect(**db_config)
                cur = conn.cursor()
                # OJO: Guardamos la ruta relativa que servirá el Proxy
                cur.execute("INSERT INTO photos (user_id, filename, storage_path) VALUES (%s,%s,%s)",
                            (session["user_id"], filename, f"/files/{filename}"))
                conn.commit()
                conn.close()
                return redirect(url_for("photos"))
            else:
                return f"Error uploading to storage: {r.status_code}"
        except Exception as e:
            return f"Connection error: {e}"
            
    return render_template("upload.html", session=session)

@app.route("/photos")
def photos():
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    conn = pymysql.connect(**db_config)
    cur = conn.cursor()
    # Obtenemos nombre de archivo
    cur.execute("SELECT filename FROM photos WHERE user_id=%s ORDER BY uploaded_at DESC", (session["user_id"],))
    rows = cur.fetchall()
    conn.close()
    
    # Pasamos 'rows' a la plantilla
    return render_template("photos.html", photos=rows, session=session)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
```
Finalizao pa'