<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$mensagem = empty($_POST['mensagem']) ? "" : $_POST['mensagem'];
$assunto = empty($_POST['assunto']) ? "" : $_POST['assunto'];
$UserEmissor = InfoUser(2);
$Comprovante = empty($_POST['Comprovante']) ? "" : $_POST['Comprovante'];
	
	if(empty($assunto)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['aeuco'], "danger");
	}
	elseif(empty($mensagem)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['meuco'], "danger");
	}
	elseif($mensagem == "<p><br></p>"){
		echo MensagemAlerta($_TRA['erro'], $_TRA['meuco'], "danger");
	}
	else{
	
	//Inserir Resposta
	$VerificarInfoOnline = VerificarInfoOnline();
	$UserReceptor = $VerificarInfoOnline[7];
	
	$SalvarMarcacao = $Comprovante == "S" ? 2 : 5;
	
	$data = time();
	$LidaEmissor = "S";
	$SQL = "INSERT INTO suporte (
			UserEmissor,
			UserReceptor,
            Assunto,
            data,
			Mensagem,
			LidaEmissor,
			Marcacao
			) VALUES (
            :UserEmissor,
			:UserReceptor,
            :Assunto,
            :data,
			:Mensagem,
			:LidaEmissor,
			:Marcacao
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':UserEmissor', $UserEmissor, PDO::PARAM_STR);
	$SQL->bindParam(':UserReceptor', $UserReceptor, PDO::PARAM_STR);
	$SQL->bindParam(':Assunto', $assunto, PDO::PARAM_STR);
	$SQL->bindParam(':data', $data, PDO::PARAM_STR);
	$SQL->bindParam(':Mensagem', $mensagem, PDO::PARAM_STR);
	$SQL->bindParam(':LidaEmissor', $LidaEmissor, PDO::PARAM_STR);
	$SQL->bindParam(':Marcacao', $SalvarMarcacao, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['mecs'], "success", "index.php?p=suporte");
	}


	}
}else{
	echo Redirecionar('login.php');
}	
?>