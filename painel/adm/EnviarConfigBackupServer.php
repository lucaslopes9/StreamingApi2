<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

//Status do Servidor
$ColunaStatusServer = array('OpcoesBackup');
$VerificarStatusServer = VerificarAcesso('opcoes', $ColunaStatusServer);
$AdminStatusServer = $VerificarStatusServer[0];

if($AdminStatusServer == 'S'){
	
$SQLServer = "SELECT * FROM server";
$SQLServer = $painel_geral->prepare($SQLServer);
$SQLServer->execute();
$LnServer = $SQLServer->fetch();

$Nome = (isset($_POST['Nome'])) ? $_POST['Nome'] : $LnServer['nome'];
$IP = (isset($_POST['IP'])) ? $_POST['IP'] : $LnServer['ip'];
$porta = (isset($_POST['porta'])) ? $_POST['porta'] : $LnServer['porta'];
$user = (isset($_POST['user'])) ? $_POST['user'] : $LnServer['user'];
$senha = (isset($_POST['senha'])) ? $_POST['senha'] : $LnServer['senha'];

	if(empty($Nome)){
		echo MensagemAlerta($_TRA['erro'], "Nome é um campo obrigatório", "danger");
	}
	elseif(empty($IP)){
		echo MensagemAlerta($_TRA['erro'], "IP é um campo obrigatório", "danger");
	}
	elseif(empty($porta)){
		echo MensagemAlerta($_TRA['erro'], "Porta é um campo obrigatório", "danger");
	}
	elseif(empty($user)){
		echo MensagemAlerta($_TRA['erro'], "Usuário é um campo obrigatório", "danger");
	}
	elseif(empty($senha)){
		echo MensagemAlerta($_TRA['erro'], "Senha é um campo obrigatório", "danger");
	}
	else{

	$SQLUrlT = "SELECT id FROM server";
	$SQLUrlT = $painel_geral->prepare($SQLUrlT);
	$SQLUrlT->execute();
	$TotalUrlT = count($SQLUrlT->fetchAll());	
	
	$HorarioInserir = time() + (3600 * $Tempo);
	
	if($TotalUrlT > 0){
	$SQL = "UPDATE server SET
			nome = :nome,
			ip = :ip,
			porta = :porta,
			user = :user,
			senha = :senha";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':nome', $Nome, PDO::PARAM_STR); 
	$SQL->bindParam(':ip', my_encrypt($IP), PDO::PARAM_STR); 
	$SQL->bindParam(':porta', my_encrypt($porta), PDO::PARAM_STR); 
	$SQL->bindParam(':user', my_encrypt($user), PDO::PARAM_STR);
	$SQL->bindParam(':senha', my_encrypt($senha), PDO::PARAM_STR);
	$SQL->execute();
	}
	else{	
	$SQL = "INSERT INTO server (
			nome,
			ip,
			porta,
			user,
			senha
            ) VALUES (
			:nome,
			:ip,
			:porta,
			:user,
			:senha
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':nome', $Nome, PDO::PARAM_STR); 
	$SQL->bindParam(':ip', my_encrypt($IP), PDO::PARAM_STR); 
	$SQL->bindParam(':porta', my_encrypt($porta), PDO::PARAM_STR); 
	$SQL->bindParam(':user', my_encrypt($user), PDO::PARAM_STR);
	$SQL->bindParam(':senha', my_encrypt($senha), PDO::PARAM_STR);
	$SQL->execute(); 
	}
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], "Servidor configurado com sucesso!", "success", "index.php?p=backup-automatizado");
	}
		
		
	}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	

?>