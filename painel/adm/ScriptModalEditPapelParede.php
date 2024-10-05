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
	
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
$pparede = empty($_POST['valor']) ? "" : $_POST['valor'];

echo "<div class=\"modal animated fadeIn\" id=\"modal_change_photo\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['apdp']."</h4>
                    </div>    
					<form id=\"cp_crop\" method=\"post\" action=\"javascript:MDouglasMS();\">
                    <div class=\"modal-body\">
						<div class=\"text-center\" id=\"cp_target\">".$_TRA['pfp']."</div>                     
                    </div>                    
                    </form>                
                    <form id=\"cp_upload\" method=\"post\" enctype=\"multipart/form-data\" action=\"upload_pparede.php\">
                    <div class=\"modal-body form-horizontal form-group-separated\">
                        <div class=\"form-group\">
                            <label class=\"col-md-4 control-label\">".$_TRA['npdp']."</label>
                            <div class=\"col-md-4\">
								<input type=\"hidden\" name=\"pparede\" id=\"pparede\" value=\"".$pparede."\"/>
                                <input type=\"file\" class=\"fileinput btn-info\" name=\"file\" id=\"cp_pparede\" data-filename-placement=\"inside\" title=\"".$_TRA['spdp']."\"/>
                            </div>                            
                        </div>                        
                    </div>
                    </form>
                    <div class=\"modal-footer\">
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>
        
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>
        
        <script type="text/javascript" src="js/plugins/jquery/jquery-migrate.min.js"></script>
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap-file-input.js"></script>
        <script type="text/javascript" src="js/plugins/form/jquery.form.js"></script>
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>
        <script type="text/javascript" src="js/plugins.js"></script>        
        <?php include_once("js/demo_edit_perfil.php"); ?>
        <!-- END TEMPLATE -->

<script>
$("#modal_change_photo").modal("show");
</script>
   
<?php  
}
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>