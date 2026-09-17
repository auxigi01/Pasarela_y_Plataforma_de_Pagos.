//ver contraseña
var ver = document.getElementById('ver');
        var input = document.getElementById('password_login');
        ver.addEventListener("click", function(){
            if(input.type =="password"){
                input.type = "text"
                ver.classList.add('ver-visible');
                }
                else{
                    input.type = "password"
                    ver.classList.remove('ver-visible');
                }
        })