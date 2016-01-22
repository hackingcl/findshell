#!/usr/bin/python
#-*- coding:UTF-8 -*-

import os
import sys
from termcolor import colored
import magic
import time

# verificamos si existe el parametro del directorio
if len(sys.argv) == 1:
	print ""
	print colored(" [-] Ingresa un directorio para analizar","red",attrs=['bold'])
	print ""
	exit()

# Directorio a analizar
directorio = sys.argv[1]

try:
	# Array de palabras que pueden ser maliciosas
	busqueda = ["eval(","getcwd(","error_reporting(","64_d","AddType","64_e","@e","system(","shell_exec(","exec(","passthru(","cmd(","phpinfo(","symlink","backdoor","safemode","gzinflate(","Shell.Exec(","assert(","proc_open(","popen(","pcntl_exec(","$_SERVER['HTTP_USER_AGENT']","preg_replace("]
	# Array imagenes analizadas
	imagen_array   = []
	# Array coincidencias
	malware_array  = []
	# Array palabra encontrada
	palabra_array  = []
	# Array linea encontrada
	linea_array    = []
	# Array total archivos analizados
	archivos_array = []
	# Array archivos ejecutables
	exec_array     = []

	# Funcion para limpiar metadatos de imagenes
	def limpiar(image):
		comando = "sudo mogrify -strip %s" % image
		os.system(comando)
		# # Al descomentar las lineas de abajo, se imprimira la ruta de todas las imagenes limpiadas
		# print colored(" Imagen limpiada --> ","green",attrs=['bold']) + image
		# print ""

	# Funcion para verificar si un archivo es malicioso
	def analizar(archivo):
		# Total de palabras a buscar
		total    = len(busqueda)
		# Abrimos el archivo
		abrir    = open(archivo)
		# Leemos el archivo
		lineas   = abrir.readlines()
		# Recorremos las lineas del archivo en busca de alguna coincidencia con el array de palabras maliciosas
		for i in xrange(0,total):
			for linea in lineas:
				palabras = linea.split(" ")
				for palabra in palabras:
						encontrado = palabra.find(busqueda[i])
						if encontrado != -1:
							print colored(" [+] Posible archivo malicioso --> ","red",attrs=['bold']) + archivo
							print ""
							print colored(" [>] Coincidencia encontrada: ","yellow",attrs=['bold']) + busqueda[i]
							print ""
							print colored(" [>] En la linea: ","yellow",attrs=['bold']) + palabra
							print colored(" +---------------------------------+","green",attrs=['bold'])
							print ""
							# Metemos la coincidnecia encontrada a los array
							malware_array.append(archivo)
							palabra_array.append(busqueda[i])
							linea_array.append(palabra)

	def inicio():
		# Mensaje de inicio
		print colored("""
	      ╔═══╗        ╔╗ ╔═══╗╔╗      ╔╗ ╔╗
	      ║╔══╝        ║║ ║╔═╗║║║      ║║ ║║
	      ║╚══╗╔╗╔══╗╔═╝║ ║╚══╗║╚═╗╔══╗║║ ║║
	      ║╔══╝╠╣║╔╗║║╔╗║ ╚══╗║║╔╗║║║═╣║║ ║║
	      ║║   ║║║║║║║╚╝║ ║╚═╝║║║║║║║═╣║╚╗║╚╗
	      ╚╝   ╚╝╚╝╚╝╚══╝ ╚═══╝╚╝╚╝╚══╝╚═╝╚═╝
		        v1.0 by @unkndown
		""","blue", attrs=['bold'])
		print colored(" [+] Iniciando analisis","green",attrs=['bold'])
		print ""

		# Array de tipos de imagenes que se analizaran
		array_content_imagen  = ["image/png","image/jpg","image/gif","image/jpeg"]	
		# Array de tipos de archivos que se analizaran
		array_content_archivo = ["application/javascript","text/html","text/x-php","text/plain"]
		# Array de tipos de archivos ejecutables
		array_content_exec    = ["application/x-executable","application/octet-stream"]

		# Recorremos el directorio, listando todos los archivos encontrados
		for (ruta, ficheros, archivos) in os.walk(directorio):
			try:
				for i in xrange(0,len(archivos)):
					archivo = ruta + "/" + archivos[i]
					mime    = magic.Magic(mime=True)
					Mtype   = mime.from_file(archivo)
					# Verificamos si el archivo es una imagen
					if Mtype in array_content_imagen:
						limpiar(archivo)
						imagen_array.append(archivo)

					# Verificamos si el archivos es archivo de texto
					elif Mtype in array_content_archivo:
						analizar(archivo)

					# Verificamos si es un archivo ejecutable
					elif Mtype in array_content_exec:
						print colored(" [+] Archivo ejecutable encontrado ---> ","cyan",attrs=['bold']) + archivo
						print ""
						print colored(" +---------------------------------+","green",attrs=['bold'])
						print ""
						exec_array.append(archivo)

					# metemos el archivo al array de total de archivos analizados
					archivos_array.append(archivo)
			except IndexError:
				# Verificamos si hubo un error en el index del ciclo
				print colored(" [-] Error en el archivo","red",attrs=['bold'])
				print ""

		# Total imagenes limpiadas
		total_imagenes = len(imagen_array)
		# Total coincidencias encontradas
		total_malware  = len(malware_array)
		# Total arcvhivos analizados
		total_archivos = len(archivos_array)

		# Estadisticas 
		print colored(" [+] Total de los archivos analizados: ","blue",attrs=['bold']) + str(total_archivos)
		print ""
		print colored(" [+] Palabras maliciosas encontradas: ","blue",attrs=['bold']) + str(total_malware)
		print ""
		print colored(" [+] Imagenes limpiadas: ","blue",attrs=['bold']) + str(total_imagenes)
		print ""
		print colored(" [+] Analisis finalizado","green",attrs=['bold'])
		print ""

	# Funcion para crear el log del script
	def log():
		# Creamos el log
		log       = open('datos.txt', 'a')
		datos = ""
		datos += "+------------------------------------------+\n"
		datos += "         " + time.strftime("%c") + "\n"
		datos += "+------------------------------------------+\n"

		for i in xrange(0,len(malware_array)):
			archivo = malware_array[i]
			linea   = linea_array[i]
			palabra = palabra_array[i]
			# Guardamos el resultado en el log
			datos += u'  '.join((" [+] Posible archivo malicioso -------> ",archivo)).encode('utf-8').strip() + "\n"
			datos += u'  '.join((" [>] Coincidencia encontrada: --------> ",palabra)).encode('utf-8').strip() + "\n"
			datos += u'  '.join((" [>] En la linea: --------------------> ",linea)).encode('utf-8').strip() + "\n\n"

		if len(exec_array) > 0:
			for i in xrange(0,len(exec_array)):
				exec_arr = exec_array[i]
				datos += u'  '.join((" [+] Archivo ejecutable encontrado: --> ",exec_arr)).encode('utf-8').strip() + "\n\n"

		# escribimos y cerramos el archivo del log
		log.write(datos)
		log.close()

	# Iniciamos el script
	if __name__ == '__main__':
	    inicio()
	    log()

except KeyboardInterrupt:
	print colored(" [+] Analisis cancelado","red",attrs=['bold'])
	print ""
