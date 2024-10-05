<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('AdminBloquear');
$VerificarAcesso = VerificarAcesso('admin', $ColunaAdmin);
$AdminBloquear = $VerificarAcesso[0];
 
if($AdminBloquear == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$CadUser = (isset($_POST['id'])) ? $_POST['id'] : '';
	$CadUserOnline = InfoUser(2);
	$ArvoreAdminOnline = ArvoreAdmin($CadUserOnline);

	if(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(!in_array($CadUser, $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$CadUser,$_TRA['npounpav']), "danger");
	}
	else{
		
	BloquearDesbloquearArvore($CadUser, "N");
	
	$bloqueado = "N";
	$SQL = "UPDATE admin SET
			bloqueado = :bloqueado
            WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQL->bindParam(':usuario', $CadUser, PDO::PARAM_STR); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['dcs'], "success", "index.php?p=administrador");
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