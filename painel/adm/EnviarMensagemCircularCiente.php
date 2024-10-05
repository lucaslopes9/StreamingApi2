<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

if(!empty($_SESSION['MensagemInterna'])){

	$usuario = InfoUser(2);
	$MensagemInterna = "";
	$SQL = "UPDATE ".SelectTabela()." SET
			MensagemInterna = :MensagemInterna
            WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':MensagemInterna', $MensagemInterna, PDO::PARAM_STR); 
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
	$SQL->execute(); 

	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		$_SESSION['MensagemInterna'] = "";
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['oemnimapv'], "success", "index.php?p=inicio");
	}


}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}

?>