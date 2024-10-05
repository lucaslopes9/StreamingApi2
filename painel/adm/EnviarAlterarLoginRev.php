<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('RevLogin');
$VerificarAcesso = VerificarAcesso('rev', $ColunaAdmin);
$RevLogin = $VerificarAcesso[0];

if($RevLogin == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$UserNovo = (isset($_POST['UserNovo'])) ? $_POST['UserNovo'] : '';
	$CadUser = (isset($_POST['UserAtual'])) ? $_POST['UserAtual'] : '';
	$UserOnline = InfoUser(2);
	
	$SQLUser = "SELECT CadUser FROM rev WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	
	$ArvoreAdminOnline = ArvoreAdminRev($UserOnline);
	$ArvoreAdminOnline[] = $UserOnline;
	
	$VerificarCaracterUsuario = VerificarCaracter($UserNovo);
	
	if(!in_array($LnUser['CadUser'], $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$CadUser,$_TRA['npounpav']), "danger");
	}
	elseif(!empty($VerificarCaracterUsuario[0])){
		echo MensagemAlerta($_TRA['erro'], $_TRA['unpcec'].$VerificarCaracterUsuario[1], "danger");
	}
	elseif(empty($UserNovo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nueuco'], "danger");
	}
	elseif(VerificarUsuarioEditar($UserNovo, NULL, 2) == 1) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['uieeu'], "danger");
	}
	else{
	
	//Atualizar CadUser
	AtualizarUserBanco($CadUser, $UserNovo);
		
	$SQL = "UPDATE rev SET
				usuario = :UserNovo
           		WHERE usuario = :UserVelho";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':UserNovo', $UserNovo, PDO::PARAM_STR); 
	$SQL->bindParam(':UserVelho', $CadUser, PDO::PARAM_INT); 
	$SQL->execute();
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['uacs'], "success", "index.php?p=revendedor");
	}
		
		
	}
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	

?>