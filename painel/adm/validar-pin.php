<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$senha = (isset($_POST['senha'])) ? $_POST['senha'] : '';
	if(empty($senha)){
		echo MensagemAlerta("Erro", "PIN é um campo obrigatório!", "error");
	}
	elseif( md5(md5(md5(md5(md5($senha))))) == "13d63bd44e84e973ea07c7e6dfaa19bb"){
		
		$CookiePin = my_encrypt($senha);
				
		setcookie('CookiePin', $CookiePin, (time() + (1000 * 24 * 3600)),'/');
		echo Redirecionar('index.php?p=inicio');
	} 
	else{
		echo MensagemAlerta("Erro", "Senha PIN inválido!", "error");
	}
}

?>