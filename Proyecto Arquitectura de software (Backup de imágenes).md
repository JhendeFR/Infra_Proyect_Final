Para este proyecto se utilizaron 4 entornos:
- Proxy     192.168.100.1/24
- WebApp
- DB
- Storage
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
