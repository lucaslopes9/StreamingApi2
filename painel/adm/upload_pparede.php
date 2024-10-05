<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('TemplatePParede');
$VerificarAcesso = VerificarAcesso('template', $ColunaAcesso);
$TemplatePParede = $VerificarAcesso[0];

if($TemplatePParede == 'S'){

$error       = false;
$ds          = DIRECTORY_SEPARATOR; 
$storeFolder = 'img'.$ds.'backgrounds';

$pparede = empty($_POST['pparede']) ? "" : $_POST['pparede'].".jpg";

if (!empty($_FILES) && $_FILES['file']['tmp_name']){    

	$VerificarPapel = getimagesize($_FILES['file']['tmp_name']);
    $LarguraP = $VerificarPapel[0];
	$AlturaP = $VerificarPapel[1];
	
	if( ($LarguraP != 1920) || ($AlturaP != 1080) ){
		echo '<div class="alert alert-danger">'.$_TRA['npopdpdpar'].'</div>';
		exit;
	}
    
    $tempFile = $_FILES['file']['tmp_name'];
    
    // check image type
    $allowedTypes = array(IMAGETYPE_JPEG);// list of allowed image types
    $detectedType = exif_imagetype($tempFile);
    $error = !in_array($detectedType, $allowedTypes);
    // end of check
    
    if(!$error){
		
		if(!empty($pparede)) unlink($storeFolder.$ds.$pparede);
        
        $targetPath = dirname( __FILE__ ) . $ds. $storeFolder . $ds;     
        $targetFile =  $targetPath. $pparede;
        
        if(move_uploaded_file($tempFile,$targetFile)){
		
        echo '<div class="cropping-image-wrap"><img src="'.$storeFolder.$ds.$pparede.'" class="img-thumbnail" id="crop_image" value="'.$pparede.'"/></div>';
        }
        
    }else{
        echo '<div class="alert alert-danger">'.$_TRA['efins'].'</div>';
    }
}else{
    echo '<div class="alert alert-danger">'.$_TRA['cvfi'].' O_o</div>';
}



}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>     
