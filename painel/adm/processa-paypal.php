<?php
include("conexao.php");
include_once("functions.php");
if(ProtegePag() == true){

$CadUser = InfoUser(4);
$descricao = empty($_POST['descricao']) ? "" : $_POST['descricao'];
$preco = empty($_POST['preco']) ? "" : trim($_POST['preco']);
$preco = number_format($preco, 2, '.', '');
$referencia = empty($_POST['referencia']) ? "" : $_POST['referencia'];
$DadosPayPal = DadosPayPal($CadUser);
?>

<form id="formulario1" name="formulario1" action="https://www.paypal.com/cgi-bin/webscr" method="post">
  
  <input type="hidden" name="cmd" value="_xclick" />
  <input type="hidden" name="business" value="<?php echo $DadosPayPal[0]; ?>" />
  <input type="hidden" name="lc" value="BR" />
  <input type="hidden" name="item_name" value="<?php echo $descricao; ?>" />
  <input type="hidden" name="item_number" value="<?php echo $referencia; ?>" />
  <input type="hidden" name="amount" value="<?php echo $preco; ?>" />
  <input type="hidden" name="currency_code" value="BRL" />
  <input type="hidden" name="no_shipping" value="1" />
  <input type="hidden" name="return" value="" />
  <input type="hidden" name="cancel_return" value="" />
  <input type="hidden" name="rm" value="0" />
  <input type="hidden" name="cbt" value="" />
  
</form>

<?php
$_SESSION['data_premio'] = "";
?>

<script language="javascript">
document.formulario1.submit();
</script>

<?php
}else{
	echo Redirecionar('login.php');
}	
?>