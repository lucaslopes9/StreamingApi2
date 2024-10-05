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
	$titulo = $_POST['titulo'];
	$data = $_POST['data'];
	$noticia = $_POST['noticia'];
		
	$SQLNOTICIAS = "INSERT INTO noticias (titulo, noticia, pdata) 
					VALUES ('$titulo', '$noticia', '$data')";
	$SQLNOTICIAS = $painel_geral->prepare($SQLNOTICIAS);
	$SQLNOTICIAS->execute();
	
	if($SQLNOTICIAS){
	echo '<div style="width: auto; margin-top: 60px;
  
  margin-right: 5%;
  margin-left: 5%;">
	<div class="alert alert-success"  role="alert">
  Noticia adicionada com sucesso!
</div></div>';
	}
}

if($NoticiaAdicionar == 'S'){

?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['grupo']; ?></li>
                    <li class="active">Adicionar Noticia</li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="col-md-12">                        
                        <div class="panel panel-default">
                                <div class="panel-heading">
                                  
                <form action="#" method="POST" role="form" class="form-horizontal">
																
                        <div class="form-group">
                            <label class="col-md-1 control-label">Titulo</label>
                            <div class="col-md-9">
                                <input type='text' name='titulo' class='form-control' placeholder='Digite o titulo' required=''>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-md-1 control-label">Data</label>
                            <div class="col-md-9">
                                <input type='date' name='data' class='form-control' placeholder='Digite o titulo' required=''>
                            </div>
                        </div>
						
						<div class="form-group">
                            <label class="col-md-1 control-label">Noticia</label>
                            <div class="col-md-9">
                                <textarea style="height: 200px" name='noticia' class='form-control' placeholder='Digite o titulo' required=''> </textarea>
								
                            </div>
                        </div>
						<div class="modal-footer">
						<div id="StatusModal"></div>
						<input class="btn btn-danger" name="41268asad" type="submit" value="Adicionar">
						</div>
						</form>
                    </div>
                    
                </div>
            </div>
        </div>                              
								</div>
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
        <script type="text/javascript" src="http://js.nicedit.com/nicEdit-latest.js"></script>
		
		<script type="text/javascript">
        bkLib.onDomLoaded(function() { nicEditors.allTextAreas() }); // convert all text areas to rich text editor on that page
       
        bkLib.onDomLoaded(function() {
             new nicEditor().panelInstance('noticia');
        }); // convert text area with id area2 to rich text editor with full panel.
</script>
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