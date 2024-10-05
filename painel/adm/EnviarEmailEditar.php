<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('EmailadicionarEditar');
$VerificarAcesso = VerificarAcesso('email_adicionar', $ColunaAcesso);
$EmailadicionarEditar = $VerificarAcesso[0];
 
if($EmailadicionarEditar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$EmailPersonalizado = (isset($_POST['EmailPersonalizado'])) ? $_POST['EmailPersonalizado'] : '';
	$EmailExibicao = (isset($_POST['EmailExibicao'])) ? $_POST['EmailExibicao'] : '';
	$EmailEmail = (isset($_POST['EmailEmail'])) ? $_POST['EmailEmail'] : '';
	$EmailSenha = (isset($_POST['EmailSenha'])) ? $_POST['EmailSenha'] : '';
	$EmailSMTP = (isset($_POST['EmailSMTP'])) ? $_POST['EmailSMTP'] : '';
	$EmailServidor = (isset($_POST['EmailServidor'])) ? $_POST['EmailServidor'] : '';
	$EmailPorta = (isset($_POST['EmailPorta'])) ? $_POST['EmailPorta'] : '';
	$EmailID = (isset($_POST['EmailID'])) ? $_POST['EmailID'] : '';
	$EmailUsuario = (isset($_POST['EmailUsuario'])) ? $_POST['EmailUsuario'] : '';
	
	$CadUser = InfoUser(2);
	$SQL = "SELECT id FROM email_adicionar WHERE CadUser = :CadUser AND email = :email AND id != :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $EmailEmail, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $EmailID, PDO::PARAM_INT);
	$SQL->execute();	
	$TotalEmail = count($SQL->fetchAll());
	
	if(empty($EmailID)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($EmailPersonalizado)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['seuco'], "danger");
	}
	elseif(empty($EmailExibicao)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['eeuco'], "danger");
	}
	elseif(empty($EmailEmail)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif(substr_count($EmailEmail, "@") == 0 || substr_count($EmailEmail, ".") == 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['fdei'], "danger");
	}
	elseif($TotalEmail > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['eeeu'], "danger");
	}
	elseif(empty($EmailUsuario)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['UCO'], "danger");
	}
	elseif(empty($EmailSMTP)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['sseuco'], "danger");
	}
	elseif(empty($EmailServidor)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['serverseuco'], "danger");
	}
	elseif(empty($EmailPorta)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['puco'], "danger");
	}
	elseif(is_numeric($EmailPorta) == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['pordcan'], "danger");
	}
	else{
		
	$SqlSenha = empty($EmailSenha) ? "" : "senha = :senha,";
	
	$SQL = "UPDATE email_adicionar SET
			servidor = :servidor,
			exibicao = :exibicao,
			email = :email,
			usuario = :usuario,
			".$SqlSenha."
			SMTPSecure = :SMTPSecure,
			Host = :Host,
			Port = :Port
            WHERE CadUser = :CadUser AND id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':servidor', $EmailPersonalizado, PDO::PARAM_STR); 
	$SQL->bindParam(':exibicao', $EmailExibicao, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $EmailEmail, PDO::PARAM_STR); 
	$SQL->bindParam(':usuario', $EmailUsuario, PDO::PARAM_STR); 
	if(!empty($EmailSenha)) $SQL->bindParam(':senha', $EmailSenha, PDO::PARAM_STR); 
	$SQL->bindParam(':SMTPSecure', $EmailSMTP, PDO::PARAM_STR); 
	$SQL->bindParam(':Host', $EmailServidor, PDO::PARAM_STR); 
	$SQL->bindParam(':Port', $EmailPorta, PDO::PARAM_INT); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $EmailID, PDO::PARAM_INT); 
	$SQL->execute(); 

	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=email-adicionar");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=email-adicionar");
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