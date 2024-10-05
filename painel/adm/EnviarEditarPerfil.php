<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if(ProtegePag() == true){
global $_TRA;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	 
$nome = (isset($_POST['nome'])) ? $_POST['nome'] : '';
$sobrenome = (isset($_POST['sobrenome'])) ? $_POST['sobrenome'] : '';
$celular = (isset($_POST['celular'])) ? $_POST['celular'] : '';
$DataNascimento = (isset($_POST['DataNascimento'])) ? ConverterData($_POST['DataNascimento'], 2) : '';

	if(empty($nome)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nuco'], "danger");
	}
	elseif(empty($sobrenome)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['suco'], "danger");
	}
	elseif(empty($celular)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cuco'], "danger");
	}
	elseif(is_numeric(LimparCelular($celular)) == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cdcan'], "danger");
	}
	elseif(empty($DataNascimento)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['duco'], "danger");
	}
	else{
		
	$id_user = InfoUser(1);
	$usuario = InfoUser(2);
	$SQL = "UPDATE ".SelectTabela()." SET
			nome = :nome,
			sobrenome = :sobrenome,
			celular = :celular,
			data_nascimento = :data_nascimento
            WHERE id = :id AND usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':nome', $nome, PDO::PARAM_STR); 
	$SQL->bindParam(':sobrenome', $sobrenome, PDO::PARAM_STR); 
	$SQL->bindParam(':celular', $celular, PDO::PARAM_STR);
	$SQL->bindParam(':data_nascimento', $DataNascimento, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id_user, PDO::PARAM_INT); 
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
	$SQL->execute(); 
	
	$_SESSION['nome'] = $nome;
	$_SESSION['sobrenome'] = $sobrenome;
	$_SESSION['celular'] = $celular;
	$_SESSION['data_nascimento'] = $DataNascimento;
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['pacs'], "success", "index.php?p=editar-perfil");
	}
		
		
	}
}

}

?>