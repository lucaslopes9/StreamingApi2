<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesVencimento');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesVencimento = $VerificarAcesso[0];
 
if($OpcoesVencimento == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$EditarTempo = (isset($_POST['EditarTempo'])) ? $_POST['EditarTempo'] : 0;
	
	$SQL = "SELECT tempo FROM tempovencimento WHERE tempo = :tempo";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':tempo', $EditarTempo, PDO::PARAM_INT); 
	$SQL->execute();
	$TotalTeste = count($SQL->fetchAll());
	
	if(empty($EditarTempo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['tempoeuco'], "danger");
	}
	elseif($TotalTeste > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['etdtje'], "danger");
	}
	elseif(is_numeric($EditarTempo) == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['tdcan'], "danger");
	}
	elseif(substr_count($EditarTempo, ".") > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['tdcani'], "danger");
	}
	else{
		
	$SQL = "INSERT INTO tempovencimento (
			tempo
            ) VALUES (
			:tempo
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':tempo', $EditarTempo, PDO::PARAM_INT);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=tempo-vencimento");
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