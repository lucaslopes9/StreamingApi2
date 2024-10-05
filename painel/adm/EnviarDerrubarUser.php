<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('StatusOnline', 'StatusDesconectado', 'StatusFalhado', 'StatusLogs', 'StatusReshare');
$VerificarAcesso = VerificarAcesso('status', $ColunaAcesso);
$StatusOnline = $VerificarAcesso[0];
$StatusDesconectado = $VerificarAcesso[1];
$StatusFalhado = $VerificarAcesso[2];
$StatusLogs = $VerificarAcesso[3];
$StatusReshare = $VerificarAcesso[4];

if( ($StatusOnline == 'S') || ($StatusDesconectado == 'S') || ($StatusFalhado == 'S') || ($StatusLogs == 'S') || ($StatusReshare == 'S') ){

	$CadUser = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
	$perfil = (isset($_POST['perfil'])) ? $_POST['perfil'] : '';
	
	$CadUserOnline = InfoUser(2);
	$ArvoreAdminOnline = ArvoreAdminRev($CadUserOnline);
	$ArvoreAdminOnline[] = $CadUserOnline;
	
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
		
		$DerrubarUsuario = DerrubarUsuario($CadUser, $perfil);
		if($DerrubarUsuario == true){
			echo "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['ok']."\">".$_TRA['ok']."</span>";
		}
		else{
			echo MensagemAlerta($_TRA['erro'], $_TRA['nfpdou'], "danger");
		}
	

	}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>