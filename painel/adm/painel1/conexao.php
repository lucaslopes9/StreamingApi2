<?php
include_once("functions.php");
ini_set('max_execution_time', 0);

include("DadosServidor.php");

// ======================================
//    ~ Conexões com Bancos de Dados ~
// ======================================
	try {
    $painel_user = new PDO('mysql:host='.$_MDouglas['servidor'].';port='.$_MDouglas['porta'].';dbname='.$_MDouglas['painel_user'].';charset=utf8', $_MDouglas['usuario'], $_MDouglas['senha'], 
	array(
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8",
	PDO::MYSQL_ATTR_INIT_COMMAND => "SET CHARACTER SET utf8"));
   $painel_acessos = new PDO('mysql:host='.$_MDouglas['servidor'].';port='.$_MDouglas['porta'].';dbname='.$_MDouglas['painel_acessos'].';charset=utf8', $_MDouglas['usuario'], $_MDouglas['senha'], 
	array(
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8",
	PDO::MYSQL_ATTR_INIT_COMMAND => "SET CHARACTER SET utf8"
  ));
  $painel_geral = new PDO('mysql:host='.$_MDouglas['servidor'].';port='.$_MDouglas['porta'].';dbname='.$_MDouglas['painel_geral'].';charset=utf8', $_MDouglas['usuario'], $_MDouglas['senha'], 
	array(
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8",
	PDO::MYSQL_ATTR_INIT_COMMAND => "SET CHARACTER SET utf8"
  ));
	} 
	catch(PDOException $e) {
    echo 'ERROR: ' . $e->getMessage();
	}
	
// ======================================
//        ~ Inicializa a Sessão ~
// ======================================
if(empty($_SESSION)){ 
	session_start(); 
}
?>