<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('ServidorcspAdicionar');
$VerificarAcesso = VerificarAcesso('servidorcsp', $ColunaAcesso);
$ServidorcspAdicionar = $VerificarAcesso[0];
 
if($ServidorcspAdicionar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$EditarNome = (isset($_POST['EditarNome'])) ? $_POST['EditarNome'] : '';
	$EditarIPurl = (isset($_POST['EditarIPurl'])) ? $_POST['EditarIPurl'] : '';
	$EditarPorta = (isset($_POST['EditarPorta'])) ? $_POST['EditarPorta'] : '';
	$EditarUsuario = (isset($_POST['EditarUsuario'])) ? $_POST['EditarUsuario'] : '';
	$EditarSenha = (isset($_POST['EditarSenha'])) ? $_POST['EditarSenha'] : '';
	$EditarProtocolo = (isset($_POST['EditarProtocolo'])) ? $_POST['EditarProtocolo'] : '';

	if(empty($EditarNome)){
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
	else{
	$SQL = "INSERT INTO painel (
			nome,
            url,
            porta,
			usuario,
			senha,
			protocolo
            ) VALUES (
            :nome, 
            :url, 
            :porta, 
			:usuario, 
			:senha, 
			:protocolo
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':nome', $EditarNome, PDO::PARAM_STR);
	$SQL->bindParam(':url', $EditarIPurl, PDO::PARAM_STR);
	$SQL->bindParam(':porta', $EditarPorta, PDO::PARAM_INT);
	$SQL->bindParam(':usuario', $EditarUsuario, PDO::PARAM_STR);
	$SQL->bindParam(':senha', $EditarSenha, PDO::PARAM_STR);
	$SQL->bindParam(':protocolo', $EditarProtocolo, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=csp");
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