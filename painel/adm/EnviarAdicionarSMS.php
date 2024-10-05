<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('SMSadicionarAdicionar');
$VerificarAcesso = VerificarAcesso('sms_adicionar', $ColunaAcesso);
$SMSadicionarAdicionar = $VerificarAcesso[0];
 
if($SMSadicionarAdicionar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$SMSUsuario = (isset($_POST['SMSUsuario'])) ? $_POST['SMSUsuario'] : '';
	$SMSSenha = (isset($_POST['SMSSenha'])) ? $_POST['SMSSenha'] : '';
	$CadUser = InfoUser(2);
	
	if(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($SMSUsuario)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['UCO'], "danger");
	}
	elseif(empty($SMSSenha)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['SCO'], "danger");
	}
	else{
	
	$bloqueado = 'S';
	$SQL = "UPDATE sms SET
			bloqueado = :bloqueado
            WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->execute(); 
		
	$SQL = "INSERT INTO sms (
			CadUser,
			user,
			senha
            ) VALUES (
            :CadUser,
			:user,
			:senha
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':user', $SMSUsuario, PDO::PARAM_STR);
	$SQL->bindParam(':senha', $SMSSenha, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=sms-adicionar");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=sms-adicionar");
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