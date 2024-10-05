<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('TesteMensagem');
$VerificarAcesso = VerificarAcesso('teste', $ColunaAcesso);
$AdminMensagem = $VerificarAcesso[0];
 
if($AdminMensagem == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$usuario = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
	$assunto = (isset($_POST['assunto'])) ? $_POST['assunto'] : '';
	$mensagem = (isset($_POST['mensagem'])) ? $_POST['mensagem'] : '';
	$EnviarCOM = (isset($_POST['EnviarCOM'])) ? $_POST['EnviarCOM'] : '';
	
	$CadUserOnline = InfoUser(2);
	$ArvoreAdminOnline = ArvoreAdminRev($CadUserOnline);
	$ArvoreAdminOnline[] = $CadUserOnline;
	$VerificarVerEmail = VerificarVerEmail($CadUserOnline);
	
	$SQLUser = "SELECT CadUser FROM teste WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	
	if(empty($assunto)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['aeuco'], "danger");
	}
	elseif(empty($mensagem)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['meuco'], "danger");
	}
	elseif($mensagem == "<p><br></p>"){
		echo MensagemAlerta($_TRA['erro'], $_TRA['meuco'], "danger");
	}
	elseif(!in_array($LnUser['CadUser'], $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$usuario,$_TRA['npounpav']), "danger");
	}
	elseif($VerificarVerEmail == 1) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['cueeeacq'], "danger");
	}
	elseif($VerificarVerEmail == 2) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['oeaesb'], "danger");
	}
	else{
		
	$CadUser = InfoUser(2);
	$bloqueado = "N";
	$SQLUser = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND id = :id";
	$SQLUser = $painel_geral->prepare($SQLUser);
	$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUser->bindParam(':id', $EnviarCOM, PDO::PARAM_STR);
	$SQLUser->execute();
	$Total = count($SQLUser->fetchAll());
	
	if($Total > 0){
		$SQLVer = "SELECT email FROM teste WHERE usuario = :usuario";
		$SQLVer = $painel_user->prepare($SQLVer);
		$SQLVer->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQLVer->execute();
		$TotalVer = count($SQLVer->fetchAll());
			
			if($TotalVer > 0){
				$SQLUser->execute();
				$LnUser = $SQLUser->fetch();
				$SQLVer->execute();
				$LnVer = $SQLVer->fetch();	
				
				$EnviarEmail = EnviarEmail($LnUser['SMTPSecure'], $LnUser['Host'], $LnUser['Port'], $LnUser['usuario'], $LnUser['senha'], $LnUser['email'], $LnUser['exibicao'], $LnVer['email'], $assunto, $mensagem, NULL);
				
				if($EnviarEmail == 1){
					echo MensagemAlerta($_TRA['sucesso'], $_TRA['mecs'], "success");
				}
				else{
					echo MensagemAlerta($_TRA['erro'], $EnviarEmail, "danger");
				}
				
			}
			else{
				echo MensagemAlerta($_TRA['erro'], $_TRA['ounpedea'], "danger");
			}
	}
	else{
		echo MensagemAlerta($_TRA['erro'], $_TRA['aoaueeea'], "danger");
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