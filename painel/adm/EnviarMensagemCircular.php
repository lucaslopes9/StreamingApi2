<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesCircular');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesCircular = $VerificarAcesso[0];
 
if($OpcoesCircular == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$Assunto = (isset($_POST['Assunto'])) ? $_POST['Assunto'] : '';
	$EnviarPara = (isset($_POST['EnviarPara'])) ? $_POST['EnviarPara'] : '';
	$Revendedor = (isset($_POST['Revendedor'])) ? $_POST['Revendedor'] : '';
	$EntreDatas = (isset($_POST['EntreDatas'])) ? $_POST['EntreDatas'] : '';
	$DataInicio = (isset($_POST['DataInicio'])) ? $_POST['DataInicio'] : '';
	$DataFinal = (isset($_POST['DataFinal'])) ? $_POST['DataFinal'] : '';
	$Grupo = (isset($_POST['Grupo'])) ? $_POST['Grupo'] : '';
	$Status = (isset($_POST['Status'])) ? $_POST['Status'] : '';
	$Mensagem = (isset($_POST['Mensagem'])) ? $_POST['Mensagem'] : '';
	$DataAtual = strtotime(date('Y-m-d'));
	$EnviarCOM = (isset($_POST['EnviarCOM'])) ? $_POST['EnviarCOM'] : '';
	
	$DataInicio = ConverterData($DataInicio, 2);
	$DataInicio = strtotime($DataInicio);
	
	$DataFinal = ConverterData($DataFinal, 2);
	$DataFinal = strtotime($DataFinal);
		
	$CadUser = InfoUser(2);
	$ArvoreAdminOnline = ArvoreAdminRev($CadUser);
	$ArvoreAdminOnline[] = $CadUser;
	
	$VerificarVerEmail = VerificarVerEmail($CadUser);
	
	if(empty($Assunto)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['aeuco'], "danger");
	}
	elseif(empty($EnviarPara)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['EnviarParaeuco'], "danger");
	}
	elseif(empty($Revendedor)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['Revendedoreuco'], "danger");
	}
	elseif(empty($EntreDatas)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['EntreDataseuco'], "danger");
	}
	elseif( ($EntreDatas == "S") && (empty($DataInicio)) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['DataInicialeuco'], "danger");
	}
	elseif( ($EntreDatas == "S") && (empty($DataFinal)) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['DataFinaleuco'], "danger");
	}
	elseif(empty($Grupo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['Grupoeuco'], "danger");
	}
	elseif(empty($Status)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['Statuseuco'], "danger");
	}
	elseif(empty($Mensagem)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['meuco'], "danger");
	}
	elseif($Mensagem == "<p><br></p>"){
		echo MensagemAlerta($_TRA['erro'], $_TRA['meuco'], "danger");
	}
	elseif(!in_array($EnviarPara, $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$EnviarPara,$_TRA['npounpav']), "danger");
	}
	elseif($VerificarVerEmail == 1) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['cueeeacq'], "danger");
	}
	elseif($VerificarVerEmail == 2) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['oeaesb'], "danger");
	}
	else{
	
	if($Revendedor == "S"){
		$EmissorAdmin = ArvoreAdmin($EnviarPara);
		$EmissorAdmin[] = $EnviarPara;
		$EmissorAdmin = implode(',', $EmissorAdmin);
		
		$EmissorRev = ArvoreRev($EnviarPara);
		$EmissorRev[] = $EnviarPara;
		$EmissorRev = implode(',', $EmissorRev);
	}
	else{
		$EmissorAdmin = $EnviarPara;
		$EmissorRev = $EnviarPara;
	}
	
	$ArrayEmail = array();
	$EnviarEmail = 0;
	$Mensagem = ModeloCircularExibir($Mensagem);
	
	if($EntreDatas == "S"){
		$SqlEntreDatas = " AND data_premio >= '".$DataInicio."' AND data_premio <= '".$DataFinal."'";
	}
	else{
		$SqlEntreDatas = "";
	}
	
	if($Status == "Ativos"){
		$PesStatus = " AND bloqueado = 'N' AND data_premio >= '".$DataAtual."'";
	}
	elseif($Status == "Bloqueados"){
		$PesStatus = " AND bloqueado = 'S'";
	}
	elseif($Status == "Esgotados"){
		$PesStatus = " AND data_premio < '".$DataAtual."'";
	}
	else{
		$PesStatus = "";
	}
		
	$SQLUserHost = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND id = :id";
	$SQLUserHost = $painel_geral->prepare($SQLUserHost);
	$SQLUserHost->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUserHost->bindParam(':id', $EnviarCOM, PDO::PARAM_STR);
	$SQLUserHost->execute();
	$LnUserHost = $SQLUserHost->fetch();
		
	//Administrador
	if($Grupo == "Todos"){
	$SQLAdmin = "SELECT usuario, email FROM admin WHERE FIND_IN_SET(usuario,:usuario)";
	$SQLAdmin = $painel_user->prepare($SQLAdmin);
	$SQLAdmin->bindParam(':usuario', $EmissorAdmin, PDO::PARAM_STR);
	$SQLAdmin->execute();
	
	while($LnAdmin = $SQLAdmin->fetch()){
		$email = $LnAdmin['email'];
		$usuario = $LnAdmin['usuario'];
		
		//Cadastrar Circular
		$SQL = "UPDATE admin SET
			MensagemInterna = :MensagemInterna
            WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':MensagemInterna', $Mensagem, PDO::PARAM_STR); 
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
		$SQL->execute(); 
		
		if(!empty($email)){
			if(!in_array($email, $ArrayEmail)) {
				$ArrayEmail[] = $email;
			}
		}
	}
	}
	
	//Revendedor
	if( ($Grupo == "rev") || ($Grupo == "Todos") ){
		$SQLRev = "SELECT usuario, email FROM rev WHERE FIND_IN_SET(usuario,:usuarioRev)".$SqlEntreDatas.$PesStatus;
		$SQLRev = $painel_user->prepare($SQLRev);
		$SQLRev->bindParam(':usuarioRev', $EmissorRev, PDO::PARAM_STR);
		$SQLRev->execute();
		
		while($LnRev = $SQLRev->fetch()){
			$email = $LnRev['email'];
			$usuario = $LnRev['usuario'];
		
			//Cadastrar Circular
			$SQL = "UPDATE rev SET
				MensagemInterna = :MensagemInterna
           		WHERE usuario = :usuario";
			$SQL = $painel_user->prepare($SQL);
			$SQL->bindParam(':MensagemInterna', $Mensagem, PDO::PARAM_STR); 
			$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
			$SQL->execute(); 
		
			if(!empty($email)){
				if(!in_array($email, $ArrayEmail)) {
					$ArrayEmail[] = $email;
				}
			}
		}
	}
	
	//Usuário
	if( ($Grupo == "Usuario") || ($Grupo == "Todos") ){
		$SQLUser = "SELECT usuario, email FROM usuario WHERE FIND_IN_SET(CadUser,:CadUserAdmin)".$SqlEntreDatas.$PesStatus." OR FIND_IN_SET(CadUser,:CadUserRev)".$SqlEntreDatas.$PesStatus;
		$SQLUser = $painel_user->prepare($SQLUser);
		$SQLUser->bindParam(':CadUserAdmin', $EmissorAdmin, PDO::PARAM_STR);
		$SQLUser->bindParam(':CadUserRev', $EmissorRev, PDO::PARAM_STR);
		$SQLUser->execute();
		
		while($LnUser = $SQLUser->fetch()){
			$email = $LnUser['email'];
			$usuario = $LnUser['usuario'];
		
			//Cadastrar Circular
			$SQL = "UPDATE usuario SET
				MensagemInterna = :MensagemInterna
           		WHERE usuario = :usuario";
			$SQL = $painel_user->prepare($SQL);
			$SQL->bindParam(':MensagemInterna', $Mensagem, PDO::PARAM_STR); 
			$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
			$SQL->execute(); 
		
			if(!empty($email)){
				if(!in_array($email, $ArrayEmail)) {
					$ArrayEmail[] = $email;
				}
			}
		}
	}
	
	//Teste
	if( ($Grupo == "Teste") || ($Grupo == "Todos") ){
		$SQLUser = "SELECT usuario, email FROM teste WHERE FIND_IN_SET(CadUser,:CadUserAdmin)".$SqlEntreDatas.$PesStatus." OR FIND_IN_SET(CadUser,:CadUserRev)".$SqlEntreDatas.$PesStatus;
		$SQLUser = $painel_user->prepare($SQLUser);
		$SQLUser->bindParam(':CadUserAdmin', $EmissorAdmin, PDO::PARAM_STR);
		$SQLUser->bindParam(':CadUserRev', $EmissorRev, PDO::PARAM_STR);
		$SQLUser->execute();
		
		while($LnUser = $SQLUser->fetch()){
			$email = $LnUser['email'];
			$usuario = $LnUser['usuario'];
		
			//Cadastrar Circular
			$SQL = "UPDATE teste SET
				MensagemInterna = :MensagemInterna
           		WHERE usuario = :usuario";
			$SQL = $painel_user->prepare($SQL);
			$SQL->bindParam(':MensagemInterna', $Mensagem, PDO::PARAM_STR); 
			$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
			$SQL->execute();
		
			if(!empty($email)){
				if(!in_array($email, $ArrayEmail)) {
					$ArrayEmail[] = $email;
				}
			}
		}
	}
					
	//Enviar Email
	if(!empty($ArrayEmail)){
		$EnviarEmail = EnviarEmailCircular($LnUserHost['SMTPSecure'], $LnUserHost['Host'], $LnUserHost['Port'], $LnUserHost['usuario'], $LnUserHost['senha'], $LnUserHost['email'], $LnUserHost['exibicao'], $ArrayEmail, $Assunto, $Mensagem);
	}
				
		if($EnviarEmail == 1){
			echo MensagemAlerta($_TRA['sucesso'], $_TRA['cecsmiee'], "success", "index.php?p=inicio");
		}
		else{
			echo MensagemAlerta($_TRA['atencao'], $_TRA['cecsmioeee'], "warning", "index.php?p=inicio");
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