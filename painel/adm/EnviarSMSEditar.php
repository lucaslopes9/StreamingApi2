<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('SMSadicionarEditar');
$VerificarAcesso = VerificarAcesso('sms_adicionar', $ColunaAcesso);
$SMSadicionarEditar = $VerificarAcesso[0];
 
if($SMSadicionarEditar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$SMSID = (isset($_POST['SMSID'])) ? $_POST['SMSID'] : '';
	$SMSUsuario = (isset($_POST['SMSUsuario'])) ? $_POST['SMSUsuario'] : '';
	$SMSSenha = (isset($_POST['SMSSenha'])) ? $_POST['SMSSenha'] : '';
	$CadUser = InfoUser(2);
	
	if(empty($SMSID)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($SMSUsuario)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['UCO'], "danger");
	}
	elseif(empty($SMSSenha)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['SCO'], "danger");
	}
	else{
	
	$SQL = "UPDATE sms SET
			user = :user,
			senha = :senha
            WHERE CadUser = :CadUser AND id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':user', $SMSUsuario, PDO::PARAM_STR); 
	$SQL->bindParam(':senha', $SMSSenha, PDO::PARAM_STR); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $SMSID, PDO::PARAM_INT); 
	$SQL->execute(); 

	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=sms-adicionar");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=sms-adicionar");
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