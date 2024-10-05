<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('NoticiaVisualizar', 'NoticiaAdicionar','NoticiaEditar', 'NoticiaExcluir');
$VerificarAcesso = VerificarAcesso('noticias', $ColunaAcesso);

$NoticiaVisualizar = $VerificarAcesso[0];
$NoticiaAdicionar = $VerificarAcesso[1];
$NoticiaEditar = $VerificarAcesso[2];
$NoticiaExcluir = $VerificarAcesso[3];

if (isset($_POST['41268asad']) )
{
	$id = $_GET['n'];
	$SQLNOTICIAS = "DELETE FROM noticias WHERE id=?";
	$SQLNOTICIAS = $painel_geral->prepare($SQLNOTICIAS);
	$SQLNOTICIAS->execute([$id]);
	if($SQLNOTICIAS){
		
	echo '<div style="width: auto; margin-top: 60px;
  
  margin-right: 5%;
  margin-left: 5%;">
	<div class="alert alert-success"  role="alert">
  Noticia excluida com sucesso!
</div></div>';
	}
}

if($NoticiaVisualizar == 'S'){

//Usuário
$CadUser = InfoUser(2);
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['grupo']; ?></li>
                    <li class="active">Noticias</li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-user"></span> Noticia</h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-default">
                                <div class="panel-heading">
                                <div class="row">
    <?php
	if( ($NoticiaAdicionar == 'S')){
	?>                       
    <div class="btn-group" style="padding:5px 0px 5px 0px;">
	<form action="#" method="POST" role="form" class="form-horizontal">
	<input class="Adicionar btn btn-danger active" name="41268asad" type="submit" value="<?php echo $_TRA['excluir']; ?>">
    </form>
	
    </div>  
    <?php
	}
	?> 
    
    </div> 
	<?php 
	if (isset($_GET['n'])) {
		$id = $_GET['n'];		
		$SQLNOTICIAS = "SELECT * FROM noticias WHERE id = $id";
		$SQLNOTICIAS = $painel_geral->prepare($SQLNOTICIAS);
		$SQLNOTICIAS->execute();
		$LnNOT = $SQLNOTICIAS->fetch();
		echo "
				<div class=\"panel-heading\">
				<h3 class=\"panel-title\" style=\"color:#563D7C\">📢<b>".$LnNOT['titulo']."</b></h3>
			  </div>
			  <div class=\"panel-body\" style=\"height: auto;\">
			  ";
		#echo "<h3>".$LnNOT['titulo']."</h3>";
		echo "✅".$LnNOT['noticia'];
		
		echo "</div>";
  
	}else{
		echo "ERROR NÃO A NOTICIA!";
	}
	

	?>

        </div>                                
      </div>
                <!-- PAGE CONTENT WRAPPER -->      
        
    

		<div id="StatusGeral"></div>        
<!-- START SCRIPTS -->
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>  
        <!-- END PLUGINS -->
        
        <script type="text/javascript" src="js/moment.min.js"></script>
        
        <script type="text/javascript" src="js/daterangepicker.js"></script>
        <link rel="stylesheet" type="text/css" href="css/daterangepicker.css" />

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->
        
        <?php 
		
		if(empty($status)){
			include_once("js/DataTablesPost".Idioma(2).".php");
		}
		else{
		?>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        <?php
		}
		
		?>
                
        <script type='text/javascript'> 
				
		</script>
          

    <!-- END SCRIPTS -->    
<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>