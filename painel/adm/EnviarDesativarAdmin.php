<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('AdminDesativar');
$VerificarAcesso = VerificarAcesso('admin', $ColunaAdmin);
$AdminDesativar = $VerificarAcesso[0];
 
if($AdminDesativar == 'S'){

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
		
	DesativarAtivarArvore($CadUser, "S");
	
	$inativo = "S";
	$SQL = "UPDATE admin SET
			inativo = :inativo
            WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':inativo', $inativo, PDO::PARAM_STR); 
	$SQL->bindParam(':usuario', $CadUser, PDO::PARAM_INT); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['d1cs'], "success", "index.php?p=administrador");
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