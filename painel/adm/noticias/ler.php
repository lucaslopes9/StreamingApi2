<?php

$SQLNOTICIAS = "SELECT * FROM noticias ORDER BY id DESC";
$SQLNOTICIAS = $painel_geral->prepare($SQLNOTICIAS);
$SQLNOTICIAS->execute();
$total = $SQLNOTICIAS->rowCount();
if ($total){

while($LnNOT = $SQLNOTICIAS->fetch()){	
	$data = $LnNOT['pdata'];
	
	echo '
		<a href="index.php?p=noticias&n='.$LnNOT['id'].'">📢'.$LnNOT['titulo'].'</a> 📆 
		<b style="color:red">Data da postagem: </b><b>'.date('d/m/Y', strtotime($data)).'</b></br>';
									
}
}else{echo "Não a noticias no momento";}
?>