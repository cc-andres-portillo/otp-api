# Project Overview - Descripcion General

## Que es

Es un servicio de verificacion en dos pasos para cuentas de usuario. Agrega una capa
adicional de seguridad al inicio de sesion: ademas de la contrasena, la persona debe
confirmar su identidad con un codigo temporal que solo ella puede obtener desde su
telefono.

## Para que sirve

Resuelve el problema de que una contrasena robada sea suficiente para entrar a una
cuenta. Con la verificacion en dos pasos activada, aunque alguien conozca la contrasena,
no puede ingresar sin el segundo codigo.

Funcionalidades principales:

- Activar la verificacion en dos pasos en una cuenta.
- Confirmar la identidad con un codigo temporal al iniciar sesion.
- Generar codigos de respaldo para usar cuando la persona no tiene acceso a su telefono.
- Desactivar la verificacion cuando el usuario lo decide.

## Como funciona

Desde la perspectiva del usuario:

1. **Activacion**: el usuario pide activar la verificacion en dos pasos. El servicio le
   entrega una imagen de codigo para escanear con una app de autenticacion en su telefono.
2. **Confirmacion**: la app del telefono empieza a mostrar un codigo numerico que cambia
   cada pocos segundos. El usuario ingresa el codigo actual una vez para confirmar que
   todo quedo bien vinculado.
3. **Codigos de respaldo**: el servicio entrega una lista de codigos de un solo uso. El
   usuario los guarda en un lugar seguro para emergencias.
4. **Uso en el dia a dia**: cada vez que el usuario inicia sesion, ademas de la
   contrasena ingresa el codigo que muestra su app en ese momento.
5. **Recuperacion**: si el usuario pierde el telefono, usa uno de los codigos de respaldo
   en lugar del codigo de la app.
6. **Desactivacion**: el usuario puede apagar la verificacion en dos pasos cuando quiera.

## Quienes lo usan

| Rol | Que hace |
|---|---|
| Usuario final | Activa, usa y desactiva la verificacion en dos pasos de su cuenta; guarda y usa codigos de respaldo |
| Sistema que lo integra | Aplicacion externa que delega en este servicio la configuracion, validacion y baja de la verificacion para sus usuarios |
| Equipo tecnico | Opera y mantiene el servicio |

## Seguridad

- **Doble comprobacion**: no alcanza con la contrasena; tambien hace falta el codigo
  temporal del telefono del usuario.
- **Codigos que caducan**: el codigo cambia cada pocos segundos, por lo que uno viejo no
  sirve para entrar.
- **Tolerancia razonable**: el servicio acepta una pequeña diferencia de reloj entre el
  telefono y el servidor, para que la verificacion no falle por unos segundos de desfase.
- **Plan de respaldo**: los codigos de recuperacion permiten recuperar el acceso si la
  persona pierde el telefono.
- **Almacenamiento controlado**: la configuracion de seguridad de cada usuario se guarda
  en un sistema de almacenamiento administrado por el equipo.

## Integracion con otros sistemas

Este servicio esta pensado para conectarse con otras aplicaciones que necesiten ofrecer
verificacion en dos pasos sin tener que construirla por su cuenta. La aplicacion que lo
integra le pide al servicio que configure, confirme, valide o desactive la verificacion
de cada usuario, y el servicio guarda y consulta esa informacion en su sistema de
almacenamiento. De esta forma, la logica de seguridad queda centralizada y reutilizable
para distintos productos.
