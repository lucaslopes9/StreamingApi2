<?php
include_once("functions.php");

//Realiza Backup Automatizado
$Backup = UrlAtual()."EnviarFazerBackupAutomatizado.php";
CurlXml($Backup,'','');

//Atualizar XML
$VerXML = UrlAtual()."EnviarVerificarXmL.php";
$CurlXml = CurlXml($VerXML,'','');

//Verificar Vencimento
$Vencimento = UrlAtual()."EnviarVerificarVencimento.php";
CurlXml($Vencimento,'','');

//Verificar Backup
$Backup = UrlAtual()."EnviarFazerBackup.php";
CurlXml($Backup,'','');