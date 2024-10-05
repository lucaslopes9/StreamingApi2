<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));

	if(ProtegePag() == true){
	global $_TRA;
	
	$ColunaRev = array('UserVisualizar');
	$VerificarAcesso = VerificarAcesso('usuario', $ColunaRev);
	$AdminVisualizar = $VerificarAcesso[0];
 
	if($AdminVisualizar == 'S'){
	
	$CadUserOnline = InfoUser(2);
	$ArvoreAdminOnline = ArvoreAdminRev($CadUserOnline);
	$ArvoreAdminOnline[] = $CadUserOnline;
	
	if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	$VerificarInfoPre = VerificarInfoPre();
	
	$SQLUser = "SELECT CadUser, data_premio, conexao FROM usuario WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $id, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	
	$data_premio = empty($LnUser['data_premio']) ? 0 : $LnUser['data_premio'];
	$Userconexao = empty($LnUser['conexao']) ? 0 : $LnUser['conexao'];
	$NovaCota = $VerificarInfoPre[1] - $Userconexao;
		
	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(!in_array($LnUser['CadUser'], $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$id,$_TRA['npounpav']), "danger");
	}
	elseif( ($NovaCota < 0) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['vntcs'], "danger");
	}
	else{	
	
	//Atualizar Cota Revendedor
	$SQLRev = "UPDATE rev SET
			Cota = :Cota
            WHERE usuario = :usuario";
	$SQLRev = $painel_user->prepare($SQLRev);                                  
	$SQLRev->bindValue(':Cota', $NovaCota); 
	$SQLRev->bindValue(':usuario', $CadUserOnline); 
	$SQLRev->execute();
	$_SESSION['Cota'] = $NovaCota;
	
	//Atualizar Tempo Usuário
	$DataAtual = time();
	
	if($data_premio < $DataAtual){
		$EditarPremium = $DataAtual + (3600 * 24 * $VerificarInfoPre[2]);
	}
	else{
		$EditarPremium = $data_premio + (3600 * 24 * $VerificarInfoPre[2]);
	}
	
	$xml = "S";
	$SQL = "UPDATE usuario SET
			data_premio = :data_premio,
			xml = :xml
            WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);                                  
	$SQL->bindValue(':data_premio', $EditarPremium); 
	$SQL->bindValue(':xml', $xml); 
	$SQL->bindValue(':usuario', $id); 
	$SQL->execute();
		
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['urcs'], "success", "index.php?p=usuario");
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