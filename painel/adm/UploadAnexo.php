<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$id_suporte = empty($_POST['id_suporte']) ? "" : $_POST['id_suporte'];
$mensagem = empty($_POST['mensagem']) ? "" : $_POST['mensagem'];
$pasta = empty($_POST['pasta']) ? "" : $_POST['pasta'];
$UserEmissor = InfoUser(2);
	
	if(empty($id_suporte)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($pasta)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($mensagem)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['meuco'], "danger");
	}
	elseif($mensagem == "<p><br></p>"){
		echo MensagemAlerta($_TRA['erro'], $_TRA['meuco'], "danger");
	}
	else{
	
	//Atualiza Receptor
	$LidaReceptor = "N";
	$SQL = "UPDATE suporte SET
			LidaReceptor = :LidaReceptor
            WHERE id = :id AND UserEmissor = :UserEmissor";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':LidaReceptor', $LidaReceptor, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id_suporte, PDO::PARAM_INT);
	$SQL->bindParam(':UserEmissor', $UserEmissor, PDO::PARAM_STR); 
	$SQL->execute();
	
	//Atualiza Emissor
	$LidaEmissor = "N";
	$SQL = "UPDATE suporte SET
			LidaEmissor = :LidaEmissor
            WHERE id = :id AND UserReceptor = :UserReceptor";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':LidaEmissor', $LidaEmissor, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id_suporte, PDO::PARAM_INT);
	$SQL->bindParam(':UserReceptor', $UserEmissor, PDO::PARAM_STR); 
	$SQL->execute();
	
	//Inserir Resposta
	$data = time();
	$SQL = "INSERT INTO suporteresp (
			id_suporte,
			UserEmissor,
            mensagem,
			data
			) VALUES (
            :id_suporte,
			:UserEmissor,
            :mensagem,
			:data
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':id_suporte', $id_suporte, PDO::PARAM_STR);
	$SQL->bindParam(':UserEmissor', $UserEmissor, PDO::PARAM_STR);
	$SQL->bindParam(':mensagem', $mensagem, PDO::PARAM_STR);
	$SQL->bindParam(':data', $data, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['mecs'], "success", "index.php?p=suporte&a=".$pasta."&m=".$id_suporte."");
	}


	}
}else{
	echo Redirecionar('login.php');
}	
?>