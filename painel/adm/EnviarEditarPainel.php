<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('ServidorcspEditar');
$VerificarAcesso = VerificarAcesso('servidorcsp', $ColunaAcesso);
$ServidorcspEditar = $VerificarAcesso[0];

if($ServidorcspEditar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$EditarID = (isset($_POST['EditarID'])) ? $_POST['EditarID'] : '';
	$EditarNome = (isset($_POST['EditarNome'])) ? $_POST['EditarNome'] : '';
	$EditarIPurl = (isset($_POST['EditarIPurl'])) ? $_POST['EditarIPurl'] : '';
	$EditarPorta = (isset($_POST['EditarPorta'])) ? $_POST['EditarPorta'] : '';
	$EditarUsuario = (isset($_POST['EditarUsuario'])) ? $_POST['EditarUsuario'] : '';
	$EditarSenha = (isset($_POST['EditarSenha'])) ? $_POST['EditarSenha'] : '';
	$EditarProtocolo = (isset($_POST['EditarProtocolo'])) ? $_POST['EditarProtocolo'] : '';
	$EditarMaxserver = (isset($_POST['EditarMaxserver'])) ? $_POST['EditarMaxserver'] : '';

	if(empty($EditarID)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($EditarNome)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nuco'], "danger");
	}
	elseif(empty($EditarIPurl)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['iuuco'], "danger");
	}
	elseif(empty($EditarPorta)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['puco'], "danger");
	}
	elseif(is_numeric($EditarPorta) == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['pordcan'], "danger");
	}
	elseif(empty($EditarUsuario)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['UCO'], "danger");
	}
	elseif(empty($EditarSenha)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['SCO'], "danger");
	}
	elseif(empty($EditarProtocolo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['prouco'], "danger");
	}	
	elseif(empty($EditarMaxserver)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['maxservererror'], "danger");
	}
	else{
		
	$SQL = "UPDATE painel SET
			nome = :nome,
			url = :url,
			porta = :porta,
			usuario = :usuario,
			senha = :senha,
			protocolo = :protocolo,
			maxserver = :maxserver
            WHERE id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':nome', $EditarNome, PDO::PARAM_STR); 
	$SQL->bindParam(':url', $EditarIPurl, PDO::PARAM_STR); 
	$SQL->bindParam(':porta', $EditarPorta, PDO::PARAM_INT); 
	$SQL->bindParam(':usuario', $EditarUsuario, PDO::PARAM_STR);
	$SQL->bindParam(':senha', $EditarSenha, PDO::PARAM_STR); 
	$SQL->bindParam(':protocolo', $EditarProtocolo, PDO::PARAM_STR);
	$SQL->bindParam(':maxserver', $EditarMaxserver, PDO::PARAM_STR);
	$SQL->bindParam(':id', $EditarID, PDO::PARAM_INT); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=csp");
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