<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;
if(ProtegePag() == true){

include("image_resizing.php");
$imgr = new imageResizing();

if($_POST['cp_img_path']){    
	
	$NomeImg = (isset($_POST['NomeImg'])) ? $_POST['NomeImg'] : '';
	
	if(empty($NomeImg)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nuco'], "danger");
	}
	else{
	
	$ds          = DIRECTORY_SEPARATOR; 
	
    $image = $_POST['cp_img_path'];
    $imgr->load($image);
    
    $imgX = intval($_POST['ic_x']);
    $imgY = intval($_POST['ic_y']);
    $imgW = intval($_POST['ic_w']);
    $imgH = intval($_POST['ic_h']);
	    
    $imgr->resize($imgW,$imgH,$imgX,$imgY);    
    $imgr->ResizePerfil(20,20); 
    $imgr->save($image);
	
	$filename = basename($_POST['cp_img_path']);
	
	//Insere a imagem no banco de dados
	$SQL = "INSERT INTO perfil_icone (
			nome,
            img
            ) VALUES (
            :nome, 
            :img
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':nome', $NomeImg, PDO::PARAM_STR);
	$SQL->bindParam(':img', $filename, PDO::PARAM_STR);
	$SQL->execute();
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ImagemAcS'], "success", "index.php?p=imagem-perfil");
	}

		}
	}
}
?>     
