<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('UserBloquear');
$VerificarAcesso = VerificarAcesso('user', $ColunaAdmin);
$AdminBloquear = $VerificarAcesso[0];

$ColunaTeste = array('TesteBloquear');
$VerificarAcessoTeste = VerificarAcesso('teste', $ColunaTeste);
$TesteBloquear = $VerificarAcessoTeste[0];
 
if( ($AdminBloquear == 'S') || ($TesteBloquear == 'S') ){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 	
	$CadUserOnline = InfoUser(2);
	$ArvoreAdminOnline = ArvoreAdminRev($CadUserOnline);
	$ArvoreAdminOnline[] = $CadUserOnline;
	$CadUser = (isset($_POST['id'])) ? $_POST['id'] : '';
	
	$SQLUser = "SELECT CadUser FROM usuario WHERE usuario = :usuario UNION SELECT CadUser FROM teste WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();

	if(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(!in_array($LnUser['CadUser'], $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$CadUser,$_TRA['npounpav']), "danger");
	}
	else{
		
	$bloqueado = "S";
	$SQL = "UPDATE usuario SET
			bloqueado = :bloqueado
            WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQL->bindParam(':usuario', $CadUser, PDO::PARAM_STR); 
	$SQL->execute(); 
	
	$SQLs = "UPDATE teste SET
			bloqueado = :bloqueado
            WHERE usuario = :usuario";
	$SQLs = $painel_user->prepare($SQLs);
	$SQLs->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQLs->bindParam(':usuario', $CadUser, PDO::PARAM_STR); 
	$SQLs->execute(); 
	
	if( empty($SQL) && empty($SQLs)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['bcs'], "success");
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